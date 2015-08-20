package Front;
use Mojo::Base 'Mojolicious';

use AccessDispatcher qw( send_request role_less_then _session);
use MainConfig qw( FILES_HOST GENERAL_URL SESSION_PORT );

my %access_rules = (
    '/'          => 'user',
    '/register'  => 'user',
    '/cargo'     => 'manager',
    '/orders'    => 'user',
    '/manage'    => 'manager',
    '/users'     => 'admin',
    '/about'     => 'user',
);

# This method will run once at server start
sub startup {
    my $self = shift;

    # Documentation browser under "/perldoc"
    $self->plugin('PODRenderer');
    $self->secrets([qw( 0i+hE8eWI0pG4DOH55Kt2TSV/CJnXD+gF90wy6O0U0k= )]);

    my $any = $self->routes->under('/' => sub {
        my $self = shift;
        my $url = $self->req->url;
        $url =~ s#^(/[^?]*)#$1#;
        $self->stash(general_url => GENERAL_URL, url => $url);

        my $res = send_request($self,
            method => 'get',
            url => 'about',
            port => SESSION_PORT,
            args => {
                user_agent => $self->req->headers->user_agent,
                session_id => $self->signed_cookie('session'),
            },
        );
        return $self->render(status => 500) unless $res;

        my %data = (
            login => '',
            name => '',
            lastname => '',
            role => '',
            uid => '',
            email => '',
        );

        if ($res->{error}) {
            _session($self, { expires => 1 });
            $self->stash(logged_in => 0);
        } else {
            %data = (%data, %$res);
            $self->stash(logged_in => 1);
        }

        $self->stash(%data);

        return 1;
    });

    my $auth = $any->under('/' => sub {
        my $self = shift;
        my $r = $self->req;

        my $url = $r->url;
        $url =~ s#^(/[^?]*)#$1#;

        unless ($self->stash('logged_in')) {
            return $self->redirect_to(GENERAL_URL . '/login');
        }

        if (!role_less_then $self->stash('role'), $access_rules{$url} || 'admin') {
            $self->render(status => 404);
            return undef;
        }

        return 1;
    });

    $any->get('/')->to("builder#index");
    $any->get('/login')->to("builder#login");
    $any->get('/register')->to("builder#register");
    $any->get('/about')->to("builder#about");
    $auth->get('/orders')->to("builder#orders");
    $auth->get('/track')->to("builder#track");
    $auth->get('/cargo')->to("builder#cargo");
    $auth->get('/manage')->to("builder#manage_orders");
    $auth->get('/users')->to("builder#users_list");

    $any->any('/*any' => { any => '' } => sub {
        my $self = shift;
        if ($self->param('any') ne 'login') {
            $self->render(status => 404);
        }
    });
}

1;
