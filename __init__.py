# COPYRIGHT (C) 2020-2024 Nicotine+ Contributors
# COPYRIGHT (C) 2011 quinox <quinox@users.sf.net>
#
# GNU GENERAL PUBLIC LICENSE
#    Version 3, 29 June 2007
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License, published by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pynicotine.pluginsystem import BasePlugin

class Plugin(BasePlugin):

    PLACEHOLDERS = {
        "%files%": "num_files",
        "%folders%": "num_folders",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Default settings
        self.settings = {
            "message": "Please consider not being a leecher. Thanks",
            "open_private_chat": False,
            "num_files": 1010,          # default minimum files
            "num_folders": 51,         # default minimum folders
            "send_message_to_leechers": False,
            "ban_leechers": True,
            "ignore_leechers": True,
            "ban_block_ip": False,
            "enable_sus_detector": True,
            "sus_pattern_500_25": False,
            "sus_pattern_1000_50": True,  # Default enabled patterns
            "sus_pattern_1500_75": False,
            "sus_pattern_2000_100": False,
            "detected_leechers": []
        }

        # Metadata settings for the plugin UI
        self.metasettings = {
            "message": {
                "description": ("Private chat message to send to leechers. Each line is sent as a separate message, "
                                "too many message lines may get you temporarily banned for spam!"),
                "type": "textview"
            },
            "open_private_chat": {
                "description": "Open chat tabs when sending private messages to leechers",
                "type": "bool"
            },
            "num_files": {
                "description": "Require users to have a minimum number of shared files:",
                "type": "int", "minimum": 0
            },
            "num_folders": {
                "description": "Require users to have a minimum number of shared folders:",
                "type": "int", "minimum": 1
            },
            "send_message_to_leechers": {
                "description": "Send a private message to users who don't meet sharing requirements",
                "type": "bool"
            },
            "ban_leechers": {
                "description": "Ban users who don't meet sharing requirements",
                "type": "bool"
            },
            "ignore_leechers": {
                "description": "Ignore users who don't meet sharing requirements",
                "type": "bool"
            },
            "enable_sus_detector": {
                "description": "Enable detection of suspicious users with fake-share patterns",
                "type": "bool"
            },
            "sus_pattern_500_25": {
                "description": "Enable detection of 500 files and 25 folders pattern",
                "type": "bool",
                "default": False
            },
            "sus_pattern_1000_50": {
                "description": "Enable detection of 1000 files and 50 folders pattern",
                "type": "bool",
                "default": True
            },
            "sus_pattern_1500_75": {
                "description": "Enable detection of 1500 files and 75 folders pattern",
                "type": "bool",
                "default": False
            },
            "sus_pattern_2000_100": {
                "description": "Enable detection of 2000 files and 100 folders pattern",
                "type": "bool",
                "default": False
            },
            "ban_sus_leechers": {
                "description": "Ban users who got caught in the sus detector",
                "type": "bool"
            },
            "ban_block_ip": {
                "description": "Block the IP of users who don't meet sharing requirements (if known)",
                "type": "bool"
            }
        }

        self.probed_users = {}

    def loaded_notification(self):
        min_num_files = self.metasettings["num_files"]["minimum"]
        min_num_folders = self.metasettings["num_folders"]["minimum"]

        if self.settings["num_files"] < min_num_files:
            self.settings["num_files"] = min_num_files
        if self.settings["num_folders"] < min_num_folders:
            self.settings["num_folders"] = min_num_folders

        self.log(
            "Require users to have a minimum of %d files and %d folders shared.",
            (self.settings["num_files"], self.settings["num_folders"])
        )

        # Build the suspicious patterns based on the user's selection
        self.settings["sus_patterns"] = []
        if self.settings["sus_pattern_1000_50"]:
            self.settings["sus_patterns"].append((1000, 50))
        if self.settings["sus_pattern_2000_100"]:
            self.settings["sus_patterns"].append((2000, 100))
        if self.settings["sus_pattern_1500_75"]:
            self.settings["sus_patterns"].append((1500, 75))
        if self.settings["sus_pattern_500_25"]:
            self.settings["sus_patterns"].append((500, 25))

        self.log("Suspicious patterns loaded: %s", self.settings["sus_patterns"])

    def send_pm(self, user):
        """Send private message to a user with placeholders replaced."""
        if not self.settings.get("send_message_to_leechers") or not self.settings.get("message"):
            return

        for line in self.settings["message"].splitlines():
            for placeholder, option_key in self.PLACEHOLDERS.items():
                line = line.replace(placeholder, str(self.settings.get(option_key, 0)))
            try:
                self.send_private(
                    user,
                    line,
                    show_ui=self.settings.get("open_private_chat", True),
                    switch_page=False
                )
            except Exception as e:
                self.log("Failed to send private message to %s: %s", (user, e))

    def block_ip(self, user):
        """Attempt to block IP if known."""
        if hasattr(self.core, "users") and hasattr(self.core.users, "watched"):
            stats = self.core.users.watched.get(user)
            if stats and getattr(stats, "ip_address", None):
                ip = stats.ip_address
                ip_list = getattr(self.core.config.sections.get("server", {}), "ipblocklist", {})
                if ip not in ip_list:
                    ip_list[ip] = user
                    self.log("Blocked IP: %s", ip)
            else:
                self.log("No stats found for user %s, cannot block IP.", user)
        else:
            self.log("IP block not possible: core.users structure missing.")

    def check_user(self, user, num_files, num_folders):
        # Normalize None → 0
        num_files = num_files or 0
        num_folders = num_folders or 0

        if user not in self.probed_users:
            return
        if self.probed_users[user] == "okay":
            return

        # Check for selected suspicious patterns (only if enabled)
        if self.settings.get("enable_sus_detector"):
            for pattern_files, pattern_folders in self.settings["sus_patterns"]:
                if num_files == pattern_files and num_folders == pattern_folders:
                    if user not in self.settings["detected_leechers"]:
                        self.settings["detected_leechers"].append(user)

                    actions = []
                    if self.settings.get("ban_sus_leechers"):
                        self.core.network_filter.ban_user(user)
                        actions.append("Banned sus")
                    if self.settings.get("ignore_leechers"):
                        self.core.network_filter.ignore_user(user)
                        actions.append("Ignored")
                    if self.settings.get("ban_block_ip"):
                        self.block_ip(user)
                        actions.append("IP blocked (if known)")
                    if self.settings.get("send_message_to_leechers"):
                        self.send_pm(user)
                        actions.append("Messaged")

                    self.probed_users[user] = "processed_leecher"

                    self.log(
                        "Suspicious sharing pattern detected: %s has exactly %d files in %d folders (likely fake shares). %s.",
                        (user, pattern_files, pattern_folders, ", ".join(actions))
                    )
                    return

        is_user_accepted = (
            num_files >= self.settings["num_files"] and
            num_folders >= self.settings["num_folders"]
        )

        if is_user_accepted or user in self.core.buddies.users:
            if user in self.settings["detected_leechers"]:
                self.settings["detected_leechers"].remove(user)
            self.probed_users[user] = "okay"
            if is_user_accepted:
                self.log("User %s is okay, sharing %s files in %s folders.", (user, num_files, num_folders))
                if self.settings.get("ban_leechers"):
                    self.core.network_filter.unban_user(user)
                if self.settings.get("ignore_leechers"):
                    self.core.network_filter.unignore_user(user)
            else:
                self.log("Buddy %s is sharing %s files in %s folders. Not complaining.", (user, num_files, num_folders))
            return

        if not self.probed_users[user].startswith("requesting"):
            return
        if user in self.settings["detected_leechers"]:
            self.probed_users[user] = "processed_leecher"
            return
        if (num_files <= 0 or num_folders <= 0) and self.probed_users[user] != "requesting_shares":
            self.log("User %s has no shared files according to the server, requesting shares to verify…", user)
            self.probed_users[user] = "requesting_shares"
            self.core.userbrowse.request_user_shares(user)
            return

        # Ban / ignore / block IP / message
        actions = []
        if self.settings.get("ban_leechers"):
            self.core.network_filter.ban_user(user)
            actions.append("banned")
        if self.settings.get("ignore_leechers"):
            self.core.network_filter.ignore_user(user)
            actions.append("ignored")
        if self.settings.get("ban_block_ip"):
            self.block_ip(user)
            actions.append("IP blocked (if known)")
        if self.settings.get("send_message_to_leechers"):
            self.send_pm(user)
            actions.append("messaged")

        self.probed_users[user] = "pending_leecher"
        if user not in self.settings["detected_leechers"]:
            self.settings["detected_leechers"].append(user)

        self.log(
            "Leecher detected: %s is only sharing %s files in %s folders. %s.",
            (user, num_files, num_folders, ", ".join(actions))
        )

    def upload_queued_notification(self, user, virtual_path, real_path):
        if user in self.probed_users:
            return
        self.probed_users[user] = "requesting_stats"
        stats = self.core.users.watched.get(user)
        if stats is None:
            return
        self.check_user(user,
                        num_files=getattr(stats, "files", 0),
                        num_folders=getattr(stats, "folders", 0))

    def user_stats_notification(self, user, stats):
        self.check_user(user,
                        num_files=stats.get("files", 0),
                        num_folders=stats.get("dirs", 0))

    def upload_finished_notification(self, user, *_):
        if user not in self.probed_users:
            return
        if self.probed_users[user] != "pending_leecher":
            return
        self.probed_users[user] = "processed_leecher"
