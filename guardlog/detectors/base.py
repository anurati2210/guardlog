"""Common interface: every detector takes an event and returns a list of alert dicts."""


class Detector:
    name = "base"

    def process(self, event):
        """Look at one Event. Return a list of alerts (dicts), possibly empty."""
        return []