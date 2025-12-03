import win32evtlog  # requires to have pywin32 installed.
import win32api
import win32con
# needed for the security permission (but still requires to run as admin).
import win32security
import ctypes
import os  # modules for checking admin rights


def checkforAdminRights():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin()


def securityPermission():
    privName = "SeSecurityPrivilege"
    privs = win32security.LookupPrivilegeValue(None, privName)
    newPrivs = [(privs, win32con.SE_PRIVILEGE_ENABLED)]

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(
    ), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
    win32security.AdjustTokenPrivileges(token, False, newPrivs)


def getTotalsOfSources(server, logTypes):
    for log in logTypes:
        evtHandle = win32evtlog.OpenEventLog(server, log)
        total = win32evtlog.GetNumberOfEventLogRecords(evtHandle)
        print("Logs in %s = %d" % (log, total))


def main(server, logTypes):
    try:
        print("Sources:\n")
        if (checkforAdminRights() != True):
            raise SystemExit("Exiting due to not running as administrator.")
        securityPermission()
        getTotalsOfSources(server, logTypes)
        logno = None
        while logno not in [0, 1, 2]:
            logno = int(input(
                "Which source would you like to use? [1 - Application, 2 - System, 3 - Security]\n>"))-1

        # this reads the logs sequentially from newest to oldest.
        evtHandle = win32evtlog.OpenEventLog(server, logTypes[logno])
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        logs = win32evtlog.ReadEventLog(evtHandle, flags, 0)

        for event in logs:
            print(f"evtID: {event.EventID}\ntime: {event.TimeGenerated}\nsource: {event.SourceName}\n"
                  f"evtCat: {event.EventCategory}\ncomputer: {event.ComputerName}\n"
                  f"recNo: {event.RecordNumber}\ntext: {event.StringInserts}")
            print("\n"+"_"*60)
    except SystemExit as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    server = None
    logTypes = ["Application", "System", "Security"]
    main(server, logTypes)
