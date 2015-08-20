package AccessDispatcher;

use strict;
use warnings;

use Carp qw(croak);
use Mojo::UserAgent;
use Mojo::Util qw( url_escape );
use Data::Dumper::OneLine;

use MainConfig qw( :all );

use base qw(Exporter);

our @EXPORT_OK = qw(
    check_access
    send_request
    check_session
    role_less_then
    _session
);

our %EXPORT_TAGS = (
    all => [@EXPORT_OK],
);

my %access_control = (
    'login' => {
        method => 'get',
        access => 'full',
        roles  => 'user',
    },

    'logout' => {
        method => 'get',
        access => 'Authorized',
        roles  => 'user',
    },

    'register' => {
        method => 'get',
        access => 'full',
        roles  => 'user',
    },

    'roles'    => {
        method => 'get',
        access  => 'Authorized',
        roles  => 'admin',
    },

    'users_list' => {
        method => 'get',
        access => 'Authorized',
        roles  => 'admin',
    },

    'cargo' => {
        method => 'get',
        access => 'Authorized',
        roles => 'manager',
    },

    'add_cargo' => {
        method => 'get',
        access => 'Authorized',
        roles => 'manager',
    },

    'orders' => {
        method => 'get',
        access => 'Authorized',
        roles => 'user',
    },

    'add_order' => {
        method => 'get',
        access => 'Authorized',
        roles => 'user',
    },

    'change_order_state' => {
        method => 'get',
        access => 'Authorized',
        roles => 'manager',
    },
);

sub _session {
    my ($self, $val) = @_;

    if (not defined $val) {
        return $self->signed_cookie('session');
    } elsif (ref $val eq 'HASH' && $val->{expires}) {
        $self->signed_cookie(session => '', { expires => 1 });
    } else {
        $self->signed_cookie(session => $val, { expires => time + EXP_TIME, domain => '.dev.web-vesna.ru', path => '/' });
    }
    return $self;
}

sub check_session {
    my $inst = shift;

    my $sid = _session $inst;
    return { logged => 0, error => 'unauthorized' } unless $sid;

    my $ua = $inst->req->headers->user_agent;

    $inst->app->log->debug("Check session ($ua)");
    my $resp = send_request($inst,
        url => 'session',
        method => 'get',
        port => SESSION_PORT,
        args => { session_id => $sid, user_agent => $ua });

    return { error => 'Internal: check_session', status => 500 } unless $resp;
    return { error => $resp->{error}, status => ($resp->{status} || 500) } if defined $resp->{error};

    return { logged => 1, uid => $resp->{uid}, role => $resp->{role} };
}

sub role_less_then {
    my ($found, $required) = @_;

    return 0 unless $found && $required;

    my %roles = ( user => 1, manager => 2, admin => 3 );
    return $roles{$required} <= $roles{$found};
}

sub check_access {
    my $inst = shift;
    my %args = (
        method => 'get',
        url => undef,
        @_,
    );

    my ($url, $method) = @args{qw( url method )};
    $inst->app->log->debug("Check access for url '$url', method '$method'");

    return { error => 'not found', description => "Can't find access rules for $url", status => 404 } unless defined $access_control{$url};

    my $r = $access_control{$url};
    return { error => "Unsupported request method for $url" }
        if $r->{method} ne 'any' and uc($r->{method}) ne uc($method);

    my $ret = {};
    $ret = check_session($inst);
    _session($inst, { expires => 1 }) if $ret->{error};
    return $ret if $ret->{error} && $ret->{error} ne 'unauthorized';

    $ret->{granted} = 1;
    return $inst->app->log->debug("Access granted") && (delete($ret->{error}) || 1) && $ret if $r->{access} eq 'full';

    if (defined $ret->{role} && !role_less_then $ret->{role}, $r->{roles}) {
        $ret = { error => "Not enough privileges to make request" };
    }
    if ($r->{access} !~ /^(Authorized|Partial)$/) {
        $ret = { error => "Unknown access type found: $r->{access} [url: $url]" };
    }

    if ($ret->{error}) {
        $inst->app->log->debug("Access denied: " . $ret->{error});
        return { error => $ret->{error} };
    }

    $inst->app->log->debug("$r->{access} access granted");
    return $ret;
}

sub send_request {
    my $inst = shift;
    my %args = (
        method => 'get',
        url => undef,
        port => undef,
        uid => undef,
        data => undef,
        headers => undef,
        @_,
    );

    my $url = $args{url};

    our %hosts = (
        SESSION_PORT()  => SESSION_HOST,
        FRONT_PORT()    => FRONT_HOST,
        LOGIC_PORT()    => LOGIC_HOST,
        DATA_PORT()     => DATA_HOST,
        FILES_PORT()    => FILES_HOST,
    );

    $args{url} = "http://$hosts{$args{port}}/$args{url}" if defined $args{url};

    croak 'url not specified' unless $args{url};

    $url = Mojo::URL->new($args{url});
    $url->port($args{port}) if defined $args{port};

    my $ua = Mojo::UserAgent->new();

    $ua->on(start => sub {
        my ($ua, $tx) = @_;
        $tx->req->headers->header(%{$args{headers}});
    }) if $args{headers};

    map { delete $args{args}->{$_} unless defined $args{args}->{$_} } keys %{$args{args}};
    $inst->app->log->debug(sprintf "Sending request [method: %s] [url: %s] [port: %d] [args: %s]",
        uc($args{method}), $args{url}, $args{port}, Dumper $args{args});

    if ($args{args}) {
        $url->query($args{args});
    }

    my @ua_args = ($url => { 'Content-Type' => $inst->req->headers->content_type } => $args{data});
    my %switch = (
        get => sub { $url->query(%{$args{args}}); return $ua->get($url); },
        post    => sub { return $ua->post(@ua_args); },
        put => sub { return $ua->put(@ua_args); },
        delete  => sub { return $ua->delete(@ua_args); },
    );

    my $s = $switch{lc $args{method}};
    croak "unknown metod specified" unless defined $s;

    my $r = $s->()->res;
    my $resp = $r->json;
    unless (defined $resp) {
        $inst->app->log->warn("Response is undefined");
        $resp = { status => $r->code, error => 'response is unknown', description => $r->message };
    } else {
        $inst->app->log->debug("Response: " . substr(Dumper($resp), 0, 512));
    }

    return wantarray ? ($resp, $args{args}->{uid}) : $resp;
}

1;
