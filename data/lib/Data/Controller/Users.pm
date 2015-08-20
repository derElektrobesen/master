package Data::Controller::Users;
use Mojo::Base 'Mojolicious::Controller';
use Mojo::JSON qw( encode_json );

use MainConfig qw( :all );
use AccessDispatcher qw( send_request check_access _session );

use Data::Dumper;

use DB qw( :all );
use Helpers qw( :all );

sub add {
    my $self = shift;

    my $params = check_params $self, qw( ulogin password uname ulastname email );
    return unless $params;

    my $_params = $self->req->params->to_hash;
    if ($_params->{user_id}) {
        $params->{role} = $_params->{role} || "user";
    } else {
        $params->{role} = "user";
    }

    my $r = select_all($self, "select id, name from roles");
    my $role_id;

    return $self->render(json => { error => "Invalid email", description => "Invalid email format" })
        unless $params->{email} =~ /^[^@]+@[^@]+$/;

    return $self->render(json => { error => "Invalid role", description => "Invalid role" })
        unless grep { $_->{name} eq $params->{role} && (($role_id = $_->{id}) || 1) } @$r;

    $r = select_row($self, "select id from users where login = ?", $params->{ulogin});
    return $self->render(json => { error => 'Invalid login', description => 'User already exists' }) if $r;

    $r = execute_query($self, "insert into users(role, login, pass, name, lastname, email) values (?, ?, ?, ?, ?, ?)",
        $role_id, @$params{qw(ulogin password uname ulastname email)});

    return return_500 $self unless $r;
    return $self->render(json => { ok => 1 });
}

sub roles {
    my $self = shift;

    my $r = select_all($self, "select name from roles order by name");
    return $self->render(json => { ok => 1, roles => $r, count => scalar @$r }) if $r;
    return return_500 $self;
}

sub list {
    my $self = shift;

    my $r = select_all($self, 'select r.name as role, u.pass as password, u.login as login, u.name as name, ' .
        'u.lastname as lastname, u.email as email from users u join roles r on r.id = u.role order by r.id, u.name');
    return return_500 $self unless $r;
    return $self->render(json => { ok => 1, count => scalar @$r, users => $r });
}

1;
