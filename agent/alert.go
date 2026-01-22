package main

import (
	"fmt"
	"time"

	"github.com/go-toast/toast"
)

func CreateAlert(alert int, caption string, msg string, score int, pid int) Alert {
	var capt string
	if caption == "" {
		capt = "Alert!"
	} else {
		capt = caption
	}
	return Alert{Type: alert, Caption: capt, Message: msg, Score: score, Pid: pid, TimeStamp: time.Now().Unix()}
}

func (a Alert) PushAlert(msg ...bool) {
	if len(msg) > 0 && msg[0] == true {
		a.PushMessage()
	} else {
		a.Print()
	}
	processes[a.Pid].IncrementScore(a.Score)
	AlertMu.Lock()
	AlertHistory = append(AlertHistory, a)
	AlertMu.Unlock()
}

// Push a toast notification of an alert, with options for further actions.
func (a Alert) PushMessage() {
	notification := toast.Notification{
		AppID:    "Genesis EDR",
		Title:    a.Caption,
		Message:  a.Message,
		Duration: toast.Long,
		Icon:     ALERT_ICON_PATH,
		Actions: []toast.Action{
			{
				Type:      "protocol",
				Label:     "Launch scan",
				Arguments: fmt.Sprintf("%s%s?pid=%d", NOTIFICATION_PREFIX, "scan", a.Pid),
			},
			{
				Type:      "protocol",
				Label:     fmt.Sprintf("Ignore %d", a.Pid),
				Arguments: fmt.Sprintf("%s%s?pid=%d", NOTIFICATION_PREFIX, "ignore", a.Pid),
			},
			{
				Type:      "protocol",
				Label:     "Terminate",
				Arguments: fmt.Sprintf("%s%s?pid=%d", NOTIFICATION_PREFIX, "kill", a.Pid),
			},
		},
	}
	notification.Push()
}

// timerange in seconds. 0 to print entire history
func PrintAlerts(timeRange int64) {
	// since you append to end, alerts should be sorted incrementally (newest last)
	for i := len(AlertHistory) - 1; i >= 0; i-- {
		now := time.Now().Unix()
		if timeRange > 0 && now-AlertHistory[i].TimeStamp > timeRange {
			return
		}
		AlertHistory[i].Print(FLAG_PRINT_INFO)
	}
}

func PrintLastAlerts(n int) {
	for i := len(AlertHistory) - 1; i > len(AlertHistory)-1-n; i-- {
		AlertHistory[i].Print(FLAG_PRINT_INFO)
	}
}

func (a Alert) Print(args ...int) {
	flags := make(map[int]bool)
	if len(args) > 0 {
		for _, f := range args {
			flags[f] = true
		}
	}
	if len(flags) == 0 {
		red.Log("\n[ALERT] ")
		white.Log("%s\n", a.Message)
		return
	}
	if flags[FLAG_PRINT_INFO] {
		stamp := time.Unix(a.TimeStamp, 0)
		fmt.Printf("\n[%s] ALERT - %s\n\t* Process Id: %d\n\t* Score: %d\n",
			stamp.Format("02-01-2006 15:04:05"), a.Message, a.Pid, a.Score)
	}
}

// This should always be used to increment score. This will handle threshold actions.
// Use score arg to choose which score gets incremented (SCORE_STATIC or SCORE_RANSOMWARE)
func (p *Process) IncrementScore(amount int, score ...int) {
	flags := make(map[int]bool)
	if len(score) > 0 {
		for _, f := range score {
			flags[f] = true
		}
	}
	p.Score.Mu.Lock()
	if flags[FLAG_RANSOMWARE] {
		p.Score.RansomScore += amount
		p.Score.Mu.Unlock()
		p.CheckThresholds()
		return
	} else if flags[FLAG_STATIC] {
		p.Score.StaticScore += amount
	}
	p.Score.TotalScore += amount
	p.Score.Mu.Unlock()
	p.CheckThresholds()
}

func (p *Process) CheckThresholds() {
	if p.Score.StaticScore > SCORE_STATIC_ALERT_THRESHOLD {
		msg := fmt.Sprintf("Static analysis score (%d) of process %d went over first threshold (%d)",
			p.Score.StaticScore, p.ProcessId, SCORE_STATIC_ALERT_THRESHOLD)
		alert := CreateAlert(ALERT_SCORE_THRESHOLD, "", msg, 0, int(p.ProcessId))
		alert.PushAlert(true) // push as toast notification
	}
	if p.Score.RansomScore > SCORE_RANSOM_ALERT_THRESHOLD {
		msg := fmt.Sprintf("Ransomware behavioral score (%d) of process %d went over first threshold (%d)",
			p.Score.RansomScore, p.ProcessId, SCORE_RANSOM_ALERT_THRESHOLD)
		alert := CreateAlert(ALERT_SCORE_THRESHOLD, "", msg, 0, int(p.ProcessId))
		alert.PushAlert(true) // push as toast notification
	}
	if p.Score.TotalScore > SCORE_TOTAL_ALERT_THRESHOLD {
		msg := fmt.Sprintf("Total behavioral score (%d) of process %d went over first threshold (%d)",
			p.Score.TotalScore, p.ProcessId, SCORE_TOTAL_ALERT_THRESHOLD)
		alert := CreateAlert(ALERT_SCORE_THRESHOLD, "", msg, 0, int(p.ProcessId))
		alert.PushAlert(true) // push as toast notification
	}

	if p.Score.StaticScore > SCORE_STATIC_FINAL_THRESHOLD {
		TerminateProcess(int(p.ProcessId))
	}
	if p.Score.RansomScore > SCORE_RANSOM_FINAL_THRESHOLD {
		TerminateProcess(int(p.ProcessId))
	}
	if p.Score.StaticScore > SCORE_TOTAL_FINAL_THRESHOLD {
		TerminateProcess(int(p.ProcessId))
	}
}
