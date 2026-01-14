import rumps
import os
import requests
import webbrowser
import subprocess

class SovereignSentinel(rumps.App):
    def __init__(self):
        super(SovereignSentinel, self).__init__("🛡️", quit_button="Quit Sovereign")
        self.menu = ["Status: Active", "Open Mission Control", "View Briefing", "Restart Guard"]
        self.timer = rumps.Timer(self.update_status, 5)
        self.timer.start()

    @rumps.clicked("Open Mission Control")
    def open_dashboard(self, _):
        webbrowser.open("http://127.0.0.1:5000")

    @rumps.clicked("View Briefing")
    def view_briefing(self, _):
        # We can trigger a notification with the report content or open dashboard
        webbrowser.open("http://127.0.0.1:5000")

    @rumps.clicked("Restart Guard")
    def restart_guard(self, _):
        try:
            requests.post("http://127.0.0.1:5000/api/restart")
            rumps.notification("Sovereign Guard", "System", "Restarting defense engines...")
        except:
            rumps.alert("Could not connect to dashboard API.")

    def update_status(self, _):
        try:
            r = requests.get("http://127.0.0.1:5000/api/learning", timeout=1)
            data = r.json()
            mode = data.get('mode', 'protect').upper()
            
            # Update Icon based on mode
            if mode == 'LEARN':
                self.title = "🎓"
            elif mode == 'WARN':
                self.title = "⚠️"
            else:
                self.title = "🛡️"
                
            self.menu["Status: Active"].title = f"Phase: {mode}"
        except:
            self.title = "⭕"
            self.menu["Status: Active"].title = "Status: OFFLINE"

if __name__ == "__main__":
    SovereignSentinel().run()

