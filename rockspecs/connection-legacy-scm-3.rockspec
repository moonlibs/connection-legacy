package = "connection-legacy"
version = "scm-3"
source = {
   url = "git://github.com/moonlibs/connection-legacy.git",
   branch = "v3"
}
description = {
   summary = "Legacy iproto connector to tarantool (1.5)",
   detailed = "Legacy iproto connector to tarantool (1.5)",
   homepage = "https://github.com/moonlibs/connection-legacy.git",
   license = "Artistic",
   maintainer = "Mons Anderson <mons@cpan.org>"
}
dependencies = {
   "lua ~> 5.1",
   "obj >= 0",
   "connection scm-3",
}
build = {
   type = "builtin",
   modules = {
      ["connection.legacy"] = "connection/legacy.lua",
      libtntlegacy = {
         sources = {
            "libtntlegacy.c"
         }
      }
   }
}
