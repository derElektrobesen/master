package Front::Controller::Builder;
use Mojo::Base 'Mojolicious::Controller';

use AccessDispatcher qw( send_request );
use MainConfig qw( :all );

sub index {
    my $self = shift;

    return $self->render(template => 'base/index');
}

sub signin_ok {
    my $self = shift;

    my $res = send_request($self,
        method => 'get',
        url => 'about',
        port => SESSION_PORT,
        args => {
            user_agent => $self->req->headers->user_agent,
            session_id => $self->signed_cookie('session'),
        },
    );

    return defined($res) && !(defined $res->{error}) && ($res->{role} ne "admin");
}

sub users_list {
    my $self = shift;

    my $res = send_request($self,
        method => 'get',
        url => 'users_list',
        port => DATA_PORT,
    );
    return $self->render(status => 500) unless $res;

    $self->stash(users => $res->{users});
    $self->render(template => 'base/users_list');
}

sub register {
    my $self = shift;

    if ($self->signin_ok) {
        return $self->redirect_to(GENERAL_URL);
    }

    return $self->render(template => 'base/reg');
}

sub about {
    my $self = shift;

    my $res = send_request($self,
        method => 'get',
        url => 'cargo',
        port => DATA_PORT,
    );

    return $self->render(status => 500) unless $res;
    $self->stash(cargo => $res->{cargo});

    return $self->render(template => 'base/about');
}

sub login {
    my $self = shift;

    if ($self->signin_ok) {
        return $self->redirect_to(GENERAL_URL);
    }

    return $self->render(template => 'base/login');
}

sub orders {
    my $self = shift;

    my $res = send_request($self,
        method => 'get',
        url => 'cargo',
        port => DATA_PORT,
    );

    return $self->render(status => 500) unless $res;
    $self->stash(cargo => $res->{cargo});

    $res = send_request($self,
        method => 'get',
        url => 'orders',
        port => DATA_PORT,
        args => { user_id => $self->stash('uid'), long => 1 },
    );
    return $self->render(status => 500) unless $res;
    $self->stash(orders => $res->{orders});

    return $self->render(template => 'base/orders');
}

sub cargo {
    my $self = shift;

    my $res = send_request($self,
        method => 'get',
        url => 'cargo',
        port => DATA_PORT,
    );
    return $self->render(status => 500) unless $res;
    $self->stash(cargo => $res->{cargo});

    return $self->render(template => 'base/cargo');
}

sub manage_orders {
    my $self = shift;

    my $res = send_request($self,
        method => 'get',
        url => 'orders',
        port => DATA_PORT,
        args => { all_users => 1 },
    );
    return $self->render(status => 500) unless $res;
    $self->stash(orders => $res->{orders});

    return $self->render(template => 'base/manage_orders');
}

1;
