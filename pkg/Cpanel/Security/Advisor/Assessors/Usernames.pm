package Cpanel::Security::Advisor::Assessors::Usernames;

# Copyright (c) 2018, cPanel, Inc.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use warnings;
use strict;

use Cpanel::Config::LoadUserOwners   ();
use Cpanel::Config::LoadUserDomains  ();
use Cpanel::ArrayFunc::Uniq          ();
use Cpanel::Validate::Username::Core ();

use base 'Cpanel::Security::Advisor::Assessors';

my $GO_URL = "https://go.cpanel.net/usernames";

my $update_user_domains_cmd = '/scripts/updateuserdomains --force';
my $rename_user_cmd         = 'whmapi1 modifyacct user=old_username newuser=new_username';

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_invalid_users;

    return 1;
}

sub _check_for_invalid_users {
    my ($self) = @_;

    my @users;

    # gather the users in /etc/trueuserowners file.
    my %trueuserowners;
    Cpanel::Config::LoadUserOwners::loadtrueuserowners( \%trueuserowners, 1, 1 );
    my @true_users = ( keys %trueuserowners );

    # gather users that exist in /var/cpanel/userdata directory
    my $user_data_dir = '/var/cpanel/userdata';
    opendir( my $userdata_dh, $user_data_dir );
    my @userdata_users = grep { $_ !~ /\A\.{1,2}\z|\Anobody\z/ && -e "$user_data_dir/$_/main" } readdir $userdata_dh;

    # find misconfigured users that have userdata but don't exist in the owners file, and vice versa.
    my %userdata_hash = map { $_ => 1 } @userdata_users;
    my @true_owner_no_userdata = grep { !$userdata_hash{$_} } @true_users;

    # gather the domain owners
    my $userdomains  = Cpanel::Config::LoadUserDomains::loaduserdomains();
    my @domain_users = ( keys %{$userdomains} );

    # find domains owners who do not have userdata or do not exist in the trueuserowners file.
    my @has_domain_no_userdata   = grep { !$userdata_hash{$_} } @domain_users;
    my @has_domain_no_true_owner = grep { !$trueuserowners{$_} } @domain_users;

    # get a list of unique users based on the previous user lists.
    my @uniq_users = Cpanel::ArrayFunc::Uniq::uniq( @true_users, @userdata_users );
    @uniq_users = Cpanel::ArrayFunc::Uniq::uniq( @uniq_users, @domain_users );

    # check for user names that do not pass validation, or are reserved.
    my @reserved;
    my @reserved_by_alias;
    my @invalid;
    my @aliases = Cpanel::Validate::Username::Core::aliases();

    foreach my $username (@uniq_users) {
        if ( Cpanel::Validate::Username::Core::reserved_username_check($username) ) {
            if ( grep { $_ =~ /\A$username\z/ } @aliases ) {
                push( @reserved_by_alias, $username );
            }
            else {
                push( @reserved, $username );
            }
        }
        elsif ( !Cpanel::Validate::Username::Core::is_valid($username) ) {
            push( @invalid, $username );
        }
    }

    @reserved          = sort_and_truncate_list(@reserved);
    @reserved_by_alias = sort_and_truncate_list(@reserved_by_alias);
    @invalid           = sort_and_truncate_list(@invalid);

    # populate all misconfigured users into a single list.
    my @misconfigured = Cpanel::ArrayFunc::Uniq::uniq( @true_owner_no_userdata, @has_domain_no_userdata, @has_domain_no_true_owner );
    @misconfigured = sort_and_truncate_list(@misconfigured);

    # display the advice
    if (@reserved) {
        $self->add_bad_advice(
            'key'        => 'Usernames_reserved',
            'text'       => $self->_lh->maketext( 'The following reserved usernames were found in use by cPanel users: [list_and,_1].', \@reserved ),
            'suggestion' => $self->_lh->maketext(
                'These usernames need to be renamed. Run “[_1]” from command line to rename these accounts. For further information about reserved usernames, please visit “[output,url,_2,Invalid and Misconfigured Usernames,_3,_4]”.',
                $rename_user_cmd,
                $GO_URL,
                "target",
                "_blank"
            )
        );
    }

    if (@reserved_by_alias) {
        $self->add_bad_advice(
            'key'        => 'Usernames_reserved_by_alias',
            'text'       => $self->_lh->maketext( 'The following cPanel usernames were found to have an email alias to a reserved username: [list_and,_1].', \@reserved_by_alias ),
            'suggestion' => $self->_lh->maketext(
                'These usernames need to be renamed or the problem aliases removed. Run “[_1]” from command line to rename these accounts. For further information about reserved usernames due to email aliases, please visit “[output,url,_2,Invalid and Misconfigured Usernames,_3,_4]”.',
                $rename_user_cmd,
                $GO_URL,
                "target",
                "_blank"
            )
        );
    }

    if (@invalid) {
        $self->add_bad_advice(
            'key'        => 'Usernames_invalid',
            'text'       => $self->_lh->maketext( 'The following cPanel usernames were found to be invalid: [list_and,_1].', \@invalid ),
            'suggestion' => $self->_lh->maketext(
                'These usernames do not match cPanel’s username validation rules and will need to be renamed. Run “[_1]” from command line to rename these accounts. To find more information about username validation rules please visit “[output,url,_2,Invalid and Misconfigured Usernames,_3,_4]”.',
                $rename_user_cmd,
                $GO_URL,
                "target",
                "_blank"
            )
        );
    }

    if (@misconfigured) {
        $self->add_bad_advice(
            'key'        => 'Usernames_misconfigured',
            'text'       => $self->_lh->maketext( 'The following cPanel usernames were found to be misconfigured: [list_and,_1].', \@misconfigured ),
            'suggestion' => $self->_lh->maketext(
                'These usernames are in an incomplete and misconfigured state. Run “[_1]” from command line to resolve these problems. For further information please visit “[output,url,_2,Invalid and Misconfigured Usernames,_3,_4]”.',
                $update_user_domains_cmd,
                $GO_URL,
                "target",
                "_blank"
            )
        );
    }

    return 1;
}

sub sort_and_truncate_list {
    @_ = sort @_;
    if ( scalar @_ > 50 ) {
        splice( @_, 50 );
        push @_, '..truncated..';
    }
    return @_;
}
1;
