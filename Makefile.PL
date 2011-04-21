use inc::Module::Install;
name 'Apache2-Authen-Redmine';
all_from 'lib/Apache2/Authen/Redmine.pm';
readme_markdown_from 'lib/Apache2/Authen/Redmine.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
