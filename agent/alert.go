package main

import (
	"fmt"
	"time"

	"github.com/go-toast/toast"
)

func CreateAlert(alert int, msg string, score int, pid int) Alert {
	return Alert{Type: alert, Msg: msg, Score: score, Pid: pid, TimeStamp: time.Now().Unix()}
}

func (a Alert) PushAlert(msg ...bool) {
	if len(msg) > 0 && msg[0] == true {
		a.PushMessage()
	} else {
		a.Print()
	}
	processes[a.Pid].ScoreMu.Lock()
	processes[a.Pid].TotalScore += a.Score
	processes[a.Pid].ScoreMu.Unlock()
	AlertMu.Lock()
	AlertHistory = append(AlertHistory, a)
	AlertMu.Unlock()
}

func (a Alert) PushMessage() {
	//TODO: enable actions from toast notification
	// actions: "Allow behavior", "Scan process", "Terminate"
	// for this you will need a notification helper program, probably.
	notification := toast.Notification{
		AppID:   "Genesis EDR",
		Title:   "Alert!",
		Message: a.Msg,
		Icon:    ALERT_ICON_PATH,
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
		white.Log("%s\n", a.Msg)
		return
	}
	if flags[FLAG_PRINT_INFO] {
		stamp := time.Unix(a.TimeStamp, 0)
		fmt.Printf("\n[%s] ALERT - %s\n\t* Process Id: %d\n\t* Score: %d\n",
			stamp.Format("02-01-2006 15:04:05"), a.Msg, a.Pid, a.Score)
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
	if flags[SCORE_RANSOMWARE] {
		p.Score.RansomScore += amount
		p.Score.Mu.Unlock()
		p.CheckThresholds()
		return
	} else if flags[SCORE_STATIC] {
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
		alert := CreateAlert(ALERT_SCORE_THRESHOLD, msg, 0, int(p.ProcessId))
		alert.PushAlert(FLAG_MESSAGE)
	}
	if p.Score.RansomScore > SCORE_RANSOM_ALERT_THRESHOLD {
		msg := fmt.Sprintf("Ransomware behavioral score (%d) of process %d went over first threshold (%d)",
			p.Score.RansomScore, p.ProcessId, SCORE_RANSOM_ALERT_THRESHOLD)
		alert := CreateAlert(ALERT_SCORE_THRESHOLD, msg, 0, int(p.ProcessId))
		alert.PushAlert()
	}
	if p.Score.TotalScore > SCORE_TOTAL_ALERT_THRESHOLD {
		msg := fmt.Sprintf("Total behavioral score (%d) of process %d went over first threshold (%d)",
			p.Score.TotalScore, p.ProcessId, SCORE_TOTAL_ALERT_THRESHOLD)
		alert := CreateAlert(ALERT_SCORE_THRESHOLD, msg, 0, int(p.ProcessId))
		alert.PushAlert()
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
