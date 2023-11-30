#!/bin/sh

IMAGE=images/client.ext4



INITSYSTEM=systemd
SIZE=1G
SKIP=,
SSHKEY=
SUITE=unstable
VMNAME=testvm

SHARE_DIR="${0%/*}/../share"

nth_arg() {
	shift "$1"
	printf "%s" "$1"
}

die() {
	echo "$*" 1>&2
	exit 1
}
usage() {
	die "usage: $0 [-h hostname] [-k sshkey] [-o output] [-r release] [-s task] [-z size] [-- mmdebstrap options]"
}
usage_error() {
	echo "error: $*" 1>&2
	usage
}

opt_architecture() {
	# This option only exists for backwards-compatibility.
	# You can pass it as mmdebstrap option instead.
	ARCHITECTURE=$1
}
opt_hostname() {
	VMNAME=$1
}
opt_initsystem() {
	case "$1" in
		busybox|finit|none|runit|systemd|sysv)
		;;
		*)
			die "value for --initsystem must be one of systemd, busybox, finit, none, runit or sysv"
		;;
	esac
	INITSYSTEM=$1
}
opt_skip() {
	if test "$1" = initsystem; then
		opt_initsystem none
	else
		SKIP="$SKIP$1,"
	fi
}
opt_sshkey() {
	SSHKEY=$1
}
opt_output() {
	IMAGE=$1
	test "${IMAGE#-}" = "$IMAGE" || IMAGE="./$IMAGE"
}
opt_release() {
	SUITE=$1
}
opt_size() {
	SIZE=$1
}

while getopts :a:h:k:o:r:s:z:-: OPTCHAR; do
	case "$OPTCHAR" in
		a)	opt_architecture "$OPTARG"	;;
		h)	opt_hostname "$OPTARG"		;;
		k)	opt_sshkey "$OPTARG"		;;
		o)	opt_output "$OPTARG"		;;
		r)	opt_release "$OPTARG"		;;
		s)	opt_skip "$OPTARG"		;;
		z)	opt_size "$OPTARG"		;;
		-)
			case "$OPTARG" in
				help)
					usage
				;;
				architecture|hostname|initsystem|output|release|size|skip|sshkey)
					test "$OPTIND" -gt "$#" && usage_error "missing argument for --$OPTARG"
					"opt_$OPTARG" "$(nth_arg "$OPTIND" "$@")"
					OPTIND=$((OPTIND+1))
				;;
				architecture=*|hostname=*|initsystem=*|output=*|release=*|size=*|skip=*|sshkey=*)
					"opt_${OPTARG%%=*}" "${OPTARG#*=}"
				;;
				*)
					usage_error "unrecognized option --$OPTARG"
				;;
			esac
		;;
		:)
			usage_error "missing argument for -$OPTARG"
		;;
		'?')
			usage_error "unrecognized option -$OPTARG"
		;;
		*)
			die "internal error while parsing command options, please report a bug"
		;;
	esac
done
shift "$((OPTIND - 1))"

if test -n "$SSHKEY" && ! test -f "$SSHKEY"; then
	die "error: ssh keyfile '$SSHKEY' not found"
fi

check_skip() {
	case "$SKIP" in
		*",$1,"*)	return 0 ;;
		*)		return 1 ;;
	esac
}

if ! check_skip kernel; then
	set -- "--customize-hook=$SHARE_DIR/customize-kernel.sh" "$@"
fi

MMFORMAT=ext2
# output a tarball if the ext4 step is skipped
if check_skip ext4; then
	MMFORMAT=tar
fi

# construct mmdebstrap options as $@:
set -- \
	--verbose \
	--variant=apt \
	"--format=$MMFORMAT" \
	'--customize-hook=echo "LABEL=debvm / ext4 defaults 0 0" >"$1/etc/fstab"' \
	"$@"

if test -n "$ARCHITECTURE"; then
	set -- "--architecture=$ARCHITECTURE" "$@"
fi

case "$INITSYSTEM" in
	busybox)
		set -- \
			--include=busybox \
			'--customize-hook=ln -s /bin/busybox $1/sbin/init' \
			"$@"
		SKIP="${SKIP}autologin,"
	;;
	finit)
		set -- --include=finit-sysv,mount "$@"
	;;
	none)
		SKIP="${SKIP}autologin,"
	;;
	runit)
		set -- --include=runit-init,passwd "$@"
	;;
	systemd)
		set -- --include=systemd-sysv "$@"
	;;
	sysv)
		set -- \
			--include=sysvinit-core \
			'--include=?not(?virtual)?exact-name(orphan-sysvinit-scripts)' \
			"$@"
	;;
esac

# set up a hostname
set -- \
	"--customize-hook=echo $VMNAME >"'"$1/etc/hostname"' \
	"--customize-hook=echo 127.0.0.1 localhost $VMNAME >"'"$1/etc/hosts"' \
	"$@"

# allow password-less root login
set -- '--customize-hook=passwd --root "$1" --delete root' "$@"

if test "$INITSYSTEM" = systemd && ! check_skip systemdnetwork; then
	# dhcp on all network interfaces, and add a dns resolver
	set -- \
		"--customize-hook=$SHARE_DIR/customize-networkd.sh" \
		'--include=?not(?virtual)?exact-name(libnss-resolve)' \
		"--customize-hook=$SHARE_DIR/customize-resolved.sh" \
		"$@"
elif test "$INITSYSTEM" = sysv -o "$INITSYSTEM" = runit -o "$INITSYSTEM" = finit && ! check_skip ifupdown; then
	set -- \
		'--include=ifupdown,isc-dhcp-client' \
		"--customize-hook=$SHARE_DIR/customize-ifupdown.sh" \
		"$@"
fi

# add ssh key for root
if test -n "$SSHKEY"; then
	set -- \
		--include=openssh-server \
		'--customize-hook=mkdir -m700 -p "$1/root/.ssh"' \
		"--customize-hook=upload $SSHKEY /root/.ssh/authorized_keys" \
		"$@"
fi

if ! check_skip packagelists; then
	set -- --skip=cleanup/apt/lists "$@"
	set -- "--customize-hook=$SHARE_DIR/customize-dpkgavailable.sh" "$@"
fi

if test "$SUITE" = jessie; then
	# Use obsolete and expired keys.
	set -- '--keyring=/usr/share/keyrings/debian-archive-removed-keys.gpg' "$@"
	set -- --aptopt='Apt::Key::gpgvcommand "/usr/libexec/mmdebstrap/gpgvnoexpkeysig"' "$@"
	set -- --hook-dir=/usr/share/mmdebstrap/hooks/jessie-or-older "$@"
fi

if ! check_skip usrmerge; then
	# Avoid the usrmerge package
	set -- --hook-dir=/usr/share/mmdebstrap/hooks/maybe-merged-usr "$@"
fi

if ! check_skip autologin; then
	set -- "--customize-hook=$SHARE_DIR/customize-autologin.sh" "$@"
fi

set -- "$SUITE" "$IMAGE" "$@"

set -ex

mmdebstrap "$@"

{ set +x; } 2>/dev/null
check_skip ext4 && exit

set -x

truncate -s ">$SIZE" "$IMAGE"
/sbin/resize2fs "$IMAGE"
/sbin/tune2fs -L debvm -c 0 -i 0 -O dir_index,dir_nlink,extents,extra_isize,flex_bg,has_journal,huge_file "$IMAGE"
/sbin/resize2fs -b "$IMAGE"
# Must fsck after tune2fs: https://ext4.wiki.kernel.org/index.php/UpgradeToExt4
/sbin/fsck.ext4 -fDp "$IMAGE"
