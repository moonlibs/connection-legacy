package = 'connection-legacy'
version = 'scm-1'

source  = {
    --url    = 'git://github.com/Mons/tnt-connection-legacy.git';
    url    = "...";
    branch = 'master';
}

description = {
    summary  = "Legacy iproto connector to tarantool (1.5)";
    detailed = "Legacy iproto connector to tarantool (1.5)";
    homepage = 'https://github.com/Mons/tnt-connection-legacy.git';
    license  = 'Artistic';
    maintainer = "Mons Anderson <mons@cpan.org>";
}

dependencies = {
    'lua >= 5.1';
}

build = {
    type = 'builtin',
    modules = {
        ['connection.legacy'] = 'connection/legacy.lua';
        ['libtntlegacy'] = {
            sources = {
                "libtntlegacy.c",
            };
        }
    }
}