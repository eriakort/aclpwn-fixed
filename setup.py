from setuptools import setup, find_packages

setup(
    name='aclpwn',
    version='0.3.4.post1',
    description='Active Directory ACL exploitation tool - Neo4j 5.x compatible fork',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Dirk-jan Mollema',
    author_email='dirk-jan@fox-it.com',
    maintainer='eriakort8',
    url='https://github.com/eriakort8/aclpwn-fixed',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'neo4j>=5.0',
        'requests',
        'impacket',
        'ldap3',
    ],
    entry_points={
        'console_scripts': [
            'aclpwn = aclpwn:main',
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
)
