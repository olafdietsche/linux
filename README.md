# Accessfs: permission filesystem for linux

Accessfs is a permission managing filesystem. It allows to control access to
system resources, based on file permissions. The recommended mount point for
this file-system is /proc/access, which will appear automatically in the
/proc filesystem.

Currently there are two modules using accessfs, userports and usercaps.

## User permission based IP ports

With userports, you will be able to control access to IP ports based
on user-/groupid.

There's no need anymore to run internet daemons as root. You can
individually configure which user/program can bind to protected ports
(by default, below 1024).

For example, you can say, user www is allowed to bind to port 80 or
user mail is allowed to bind to port 25. Then, you can run apache as
user www and sendmail as user mail. Now, you don't have to rely on
apache or sendmail giving up superuser rights to enhance security.

To use this option, you need to mount the access file system
and do a chown on the appropriate ports:

    mount -t accessfs none /proc/access
    chown www /proc/access/net/ip/bind/80
    chown mail /proc/access/net/ip/bind/25

You can grant access to a group for individual ports as well. Just say:

    chgrp lp /proc/access/net/ip/bind/515
    chown g+x /proc/access/net/ip/bind/515

## User permission based capabilities

With usercaps, you will be able to grant capabilities based on
user-/groupid (root by default).

For example you can create a group `raw` and change the capability
`net_raw` to this group:

    chgrp raw /proc/access/capabilities/net_raw
    chmod ug+x /proc/access/capabilities/net_raw
    chgrp raw /sbin/ping
    chmod u-s /sbin/ping; chmod g+s /sbin/ping
