package Apache2::Authen::Redmine;

# Most part of this code is borrowed from Tim Bunce's Apache2::AuthPAM module.

use strict;
use warnings;

use Apache2::Const qw/:common/;
use Apache2::RequestRec  ();
use Apache2::RequestUtil (); 
use Apache2::Access      ();
use Apache2::Log         ();

use DBI;
use Digest::SHA qw/sha1_hex/;

our $VERSION = '0.01';
our $MODNAME = __PACKAGE__;


sub handler {
    my $r = shift;
    
    # check first request
    return OK unless $r->is_initial_req;
    
    # get user password
    my ($rc, $pw) = $r->get_basic_auth_pw;
    
    # decline if not basic
    return $rc if $rc;
    
    # get log object
    my $log = $r->log;
    
    # get user name
    my $username = $r->user;
    
    # avoid blank username
    unless($username) {
        $r->note_basic_auth_failure;
        $log->info("$MODNAME: no user name supplied", $r->uri);
        return AUTH_REQUIRED;
    }
    
    my $dh = DBI->connect_cached(
        $r->dir_config->get('redmine_dsn'),
        $r->dir_config->get('redmine_user'),
        $r->dir_config->get('redmine_password'),
    )  or die $DBI::errstr;
    my @row = $dbi->selectrow_array(
        'SELECT id FROM users WHERE status = 1 AND login = ? AND hashed_password = ?',
        {},
        $username, sha1_hex($pw)
    );
    return OK  if @row;
    
    return AUTH_REQUIRED;
}


1;
__END__

=head1 NAME

Apache2::Authen::Redmine - Basic authentication by Redmine accounts

=head1 SYNOPSIS

  <Location /to/protect>
    PerlAuthenHandler Apache2::Authen::Redmine
    PerlSetVar redmine_dsn      dbi:mysql:database=redmine;host=localhost;port=3306
    PerlSetVar redmine_user     dbuser
    PerlSetVar redmine_password dbpasswd

    AuthType Basic
    AuthName "Protected area"
    Require  valid-user
  </Location>

=head1 DESCRIPTION

Apache2::Authen::Redmine allows you to authenticate requests with using
login-name and password of Redmine.

Many of our projects used Subverion as for SCM and Redmine for BTS, and
hosted both of them by Apache server. In those days, we used to maintain
login information for Subversion repositories using classic htpasswd
command, wheres Redmine also has its own login information.
After a while, that maintenance became heavily cumbersome, as you can
expected.

Thus, this module was born!

=head1 CONFIGURATION

Just described in L</SYNOPSIS>, use C<PerlAuthenHandler> directive in your
directory where you want to require password authentication to access.
Besides, you need to set the following configuration variables using
C<PerlSetVar> directive.

=head2 redmine_dsn

  PerlSetVar redmine_dsn dbi:dbd:database;attrs

Specify DSN to access your Redmine's database.
See also L<DBI>.

=head2 redmine_user
  
  PerlSetVar redmine_user user_name

Specify user name to access your Redmine's database.

=head2 redmine_password

  PerlSetVar redmine_password password

Specify password to access your Redmine's database.

=head1 CAVEAT

B<THIS MODULE IS VERY DIRTY> since it makes direct access to Redmine's
database.

It is better to use LDAP than this module for centralizing authentication
information. LDAP is a clean and standard way to do it, and of course
supported by Redmine.

But, configuring and maintaining LDAP server is complicated work. So, this
module is still convenient for users who want to avoid complex work and
looking for a simple solution.

=head1 WHY Perl?

Why this module is implemented in Perl wheres Redmine is implemented in
Ruby? The reason is just I like Perl.

Do you need any other reason?

=head1 AUTHOR

Daisuke (yet another) Maki E<lt>yanother {at} cpan.orgE<gt>

=head1 SEE ALSO

L<mod_perl 2.0 Server Configuration|http://perl.apache.org/docs/2.0/user/config/config.html>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

