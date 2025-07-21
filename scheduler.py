#!/usr/bin/env python3
"""
Daily LinkedIn CVE Bot Scheduler
This script manages daily posting schedules and ensures content variety
"""

import os
import time
import schedule
import logging
from datetime import datetime, timedelta
from processor import CyberSecurityProcessor
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("scheduler.log"),
        logging.StreamHandler()
    ]
)

class ContentScheduler:
    """Manages daily cybersecurity content posting schedule."""
    
    def __init__(self):
        self.posting_times = [
            "09:00"   # Morning business hours (daily security briefing)
        ]
        self.max_daily_posts = 1
        self.daily_post_count = 0
        self.last_post_date = None
        
    def reset_daily_counter(self):
        """Reset daily post counter at midnight."""
        current_date = datetime.now().date()
        if self.last_post_date != current_date:
            self.daily_post_count = 0
            self.last_post_date = current_date
            logging.info(f"Reset daily post counter for {current_date}")
    
    def can_post_today(self):
        """Check if we can still post today."""
        self.reset_daily_counter()
        return self.daily_post_count < self.max_daily_posts
    
    def post_cybersecurity_content(self):
        """Execute a single cybersecurity post."""
        if not self.can_post_today():
            logging.info(f"Daily post limit reached ({self.max_daily_posts}). Skipping post.")
            return False
        
        try:
            logging.info("Starting scheduled cybersecurity post...")
            processor = CyberSecurityProcessor()
            
            # Add random delay to appear more human
            delay = random.randint(60, 300)  # 1-5 minutes
            logging.info(f"Adding random delay of {delay} seconds...")
            time.sleep(delay)
            
            # Process topics
            processor.process_cybersecurity_topics()
            
            self.daily_post_count += 1
            logging.info(f"Post completed successfully. Daily count: {self.daily_post_count}/{self.max_daily_posts}")
            
            return True
            
        except Exception as e:
            logging.error(f"Error during scheduled post: {e}", exc_info=True)
            return False
        finally:
            pass
    
    def schedule_posts(self):
        """Set up the posting schedule."""
        logging.info("Setting up LinkedIn morning posting schedule...")
        
        # Schedule single morning post
        schedule.every().day.at(self.posting_times[0]).do(self.post_cybersecurity_content)
        logging.info(f"📅 Scheduled daily morning briefing at {self.posting_times[0]}")
        
        # Schedule daily counter reset at midnight
        schedule.every().day.at("00:01").do(self.reset_daily_counter)
        
        logging.info("Schedule setup complete!")
    
    def run(self):
        """Start the scheduler."""
        self.schedule_posts()
        
        logging.info("Cybersecurity Content Scheduler started...")
        org_urn = os.getenv("LINKEDIN_ORG_URN", "")
        logging.info(f"Posting to: {'Company page' if org_urn else 'Personal profile'}")
        logging.info(f"Daily post limit: {self.max_daily_posts}")
        logging.info(f"Morning posting time: {self.posting_times[0]} (daily security briefing)")
        
        while True:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
                
                # Log next scheduled job occasionally
                if datetime.now().minute == 0:  # Every hour
                    next_job = schedule.next_run()
                    if next_job:
                        logging.info(f"Next scheduled post: {next_job}")
                        
            except KeyboardInterrupt:
                logging.info("Scheduler stopped by user")
                break
            except Exception as e:
                logging.error(f"Scheduler error: {e}", exc_info=True)
                time.sleep(300)  # Wait 5 minutes before retrying

def run_single_post():
    """Run a single post for testing."""
    scheduler = ContentScheduler()
    logging.info("Running single test post...")
    success = scheduler.post_cybersecurity_content()
    if success:
        logging.info("Test post completed successfully!")
    else:
        logging.error("Test post failed!")
    return success

def main():
    """Main function to handle command line arguments."""
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "test":
            # Run a single test post
            return run_single_post()
        elif command == "schedule":
            # Run the scheduler
            scheduler = ContentScheduler()
            scheduler.run()
        else:
            print("Usage:")
            print("  python scheduler.py test      - Run a single test post")
            print("  python scheduler.py schedule  - Start daily scheduler")
            print("  python scheduler.py           - Start daily scheduler (default)")
    else:
        # Default: run scheduler
        scheduler = ContentScheduler()
        scheduler.run()

if __name__ == "__main__":
    main() 