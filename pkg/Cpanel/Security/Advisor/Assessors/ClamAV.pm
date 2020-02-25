package Cpanel::Security::Advisor::Assessors::ClamAV;

# Copyright (c) 2013, cPanel, Inc.
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
# DISCLAIMED. IN NO EVENT SHALL cPanel, L.L.C. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use Cpanel::FindBin         ();
use Cpanel::SafeRun::Errors ();
use Cpanel::Version         ();

use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;

    my $cpanel_version = Cpanel::Version::getversionnumber();

    # Only show the clamav advice if running version 86 and lower.
    # Otherwise we will recommend ImunifyAV in the Imunify360 module.
    if ( Cpanel::Version::compare( $cpanel_version, '<=', '11.86' ) ) {
        return 0 if $self->_check_clamav();
    }
    return 1;
}

sub _check_clamav {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $install_clamav = 'scripts2/manage_plugins';

    $self->_find_clamav();

    if ( !$self->{clamav}{clamscan}{bin} && !$self->{clamav}{freshclam}{bin} ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'ClamAV_not_installed',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('ClamAV is not installed.'),
                'suggestion' => $self->_lh->maketext(
                    'Install ClamAV within "[output,url,_1,Manage Plugins,_2,_3]".',
                    $self->base_path($install_clamav), 'target', '_blank',
                ),
            }
        );
    }
    elsif ( !$self->{clamav}{clamscan}{bin} ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'ClamAV_binary_not_installed',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('ClamAV clamscan binary is not installed.'),
                'suggestion' => $self->_lh->maketext(
                    'Install ClamAV within "[output,url,_1,Manage Plugins,_2,_3]".',
                    $self->base_path($install_clamav), 'target', '_blank',
                ),
            }
        );
    }
    elsif ( !$self->{clamav}{freshclam}{bin} ) {
        $security_advisor_obj->add_advice(
            {
                'key'        => 'ClamAV_freshclam_not_installed',
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => $self->_lh->maketext('ClamAV freshclam binary is not installed.'),
                'suggestion' => $self->_lh->maketext(
                    'Install ClamAV within "[output,url,_1,Manage Plugins,_2,_3]".',
                    $self->base_path($install_clamav), 'target', '_blank',
                ),
            }
        );
    }
    else {
        $self->_get_clam_version();

        my @bad_clams;

        push( @bad_clams, 'clamscan' )  if !defined $self->{clamav}{clamscan}{version};
        push( @bad_clams, 'freshclam' ) if !defined $self->{clamav}{freshclam}{version};

        if (@bad_clams) {

            $security_advisor_obj->add_advice(
                {
                    'key'        => 'ClamAV_failed_to_get_version',
                    'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text'       => $self->_lh->maketext( 'Failed to get version for [list_and,_1].', \@bad_clams ),
                    'suggestion' => $self->_lh->maketext(
                        'clamscan version: [_1]<br/>freshclam version: [_2]<br/><br/>Reinstall ClamAV within "[output,url,_3,Manage Plugins,_4,_5]".', $self->{clamav}{clamscan}{version_str}, $self->{clamav}{freshclam}{version_str}, $self->base_path($install_clamav), 'target', '_blank',
                    ),
                }
            );

            return $self;
        }

        if ( $self->{clamav}{clamscan}{version} ne $self->{clamav}{freshclam}{version} ) {
            $security_advisor_obj->add_advice(
                {
                    'key'        => 'ClamAV_freshclam_and_clamscan_binaries_different_versions',
                    'type'       => $Cpanel::Security::Advisor::ADVISE_WARN,
                    'text'       => $self->_lh->maketext('ClamAV freshclam and clamscan binaries are different versions.'),
                    'suggestion' => $self->_lh->maketext(
                        'clamscan version: [_1]<br/>freshclam version: [_2]<br/><br/>Reinstall ClamAV within "[output,url,_3,Manage Plugins,_4,_5]".', $self->{clamav}{clamscan}{version_str}, $self->{clamav}{freshclam}{version_str}, $self->base_path($install_clamav), 'target', '_blank',
                    ),
                }
            );
        }
    }
    return $self;
}

sub _find_clamav {
    my ($self) = @_;

    my @paths = qw{ /usr/local/cpanel/3rdparty/bin /usr/bin /usr/local/bin /bin /sbin /usr/sbin /usr/local/sbin };

    $self->{clamav}{clamscan}{bin}  = Cpanel::FindBin::findbin( 'clamscan',  'path' => @paths );
    $self->{clamav}{freshclam}{bin} = Cpanel::FindBin::findbin( 'freshclam', 'path' => @paths );

    return $self;
}

sub _get_clam_version {
    my ($self) = @_;

    foreach my $clam ( 'clamscan', 'freshclam' ) {
        chomp( my $version = Cpanel::SafeRun::Errors::saferunallerrors( $self->{clamav}{$clam}{bin}, '-V' ) );
        $self->{clamav}{$clam}{version_str} = $version || 'Failed to obtain version!';
        if ( $version =~ /^ClamAV (\d+\.\d+\.\d+)/m ) {
            $self->{clamav}{$clam}{version} = $1;
        }
    }

    return $self;
}

1;
