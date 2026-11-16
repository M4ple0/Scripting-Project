"""Rule-based analysis: one small script per family of security checks.

Every script in this package (except ``base`` and ``engine``) must define:

    NAME         short name of the check family
    DESCRIPTION  one line saying what it looks for
    RULES        list of ``base.Rule`` objects (used for documentation / --list-rules)
    check(code)  takes a CodeInput and returns a list of Finding objects

Drop a new script in this folder and ``engine`` picks it up automatically.
"""
