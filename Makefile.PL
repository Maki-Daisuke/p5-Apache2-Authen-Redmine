use inc::Module::Install;
name 'Apache2-Authen-Redmine';
all_from 'lib/Apache2/Authen/Redmine.pm';
readme_markdown_from 'lib/Apache2/Authen/Redmine.pm';

perl_version   '5.010';

requires       'DBI';
requires       'mod_perl2'    => '2.000004';
requires       'Digest::SHA'  => '5.47';

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
auto_set_repository;
WriteAll;

