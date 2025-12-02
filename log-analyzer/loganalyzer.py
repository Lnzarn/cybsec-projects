import win32evtlog  # requires to have pywin32 installed.
import win32api
import win32con
import win32security


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
    print("Sources:\n")
    securityPermission()
    getTotalsOfSources(server, logTypes)

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


if __name__ == "__main__":
    server = None
    logTypes = ["Application", "System", "Security"]
    main(server, logTypes)
