import praw
import datetime
import sys
import traceback
from config import smbconstants as config

config.SUBREDDIT = config.SUBREDDIT.lower()
TIMELAPSE = config.NUM_HOURS * 60 * 60
VALID_ADMINS = [config.ADMIN_USER]
EXCLUDED_SUBREDDITS = [config.SUBREDDIT]
BOT_COMMANDS = { 'status': 'reply_status()',
                 'timeframe': 'change_timelapse(cmd[1])',
                 'exclude': 'add_exclusion(cmd[1])',
                 'include': 'remove_exclusion(cmd[1])' }
BOT_REPLIES = { 'status': 'reply_status_content(mentions, msg.author, last_time)',
                'timeframe': 'timeframe_updated(cmd[1], msg.author, last_time)',
                'exclude': 'exclusion_added(cmd[1], msg.author)',
                'include': 'exclusion_removed(cmd[1], msg.author)' }
BOT_SYNTAX = { 'STATUS': 'Send an immediate status message with the current number of mentions across Reddit. Does **not** restart the clock timer, so you may see these mentions again in the next regularly scheduled message.',
               'TIMEFRAME #': 'where `#` is an integer representing the number of hours for periodic updates. If shortened, the bot may send an immediate message. Otherwise, the current cycle will respect the new timeframe.',
               'EXCLUDE [subreddit_name]': 'Adds the given subreddit (without the `r/`) to the exclusion list. Mentions on that subreddit will no longer be reported.',
               'INCLUDE [subreddit_name]': 'Removes the given subreddit (without the `r/`) from the exclusion list. Mentions on that subreddit will be reported again.' }
# command variables
result = 0
reply_msg = ''

def switch(dictionary, default, value):
    return dictionary.get(value, default)

def bot_signature():
    message = '\n\nThanks for using the Brigade Warning Bot!\n\nRemember that you can reply to this message,'
    message += ' or send a new private message to this bot, in order to make adjustments to how'
    message += ' it operates. Send a single command per message with the command as the complete'
    message += ' subject OR complete body of the message.\n\nEach of these commands is case-'
    message += 'insensitive:\n\n'
    for cmd,syntax in BOT_SYNTAX.items():
        message += '* `' + cmd + '`: ' + syntax + '\n'
    message += '\nPlease send a message to /u/' + config.ADMIN_USER + ' if you have any questions.'
    return message

def change_timelapse(new_timelapse):
    # new_timelapse: in hours
    if not isinstance(new_timelapse, int):
        return -1
    if new_timelapse <= 0:
        return -1
    TIMELAPSE = new_timelapse * 60 * 60
    return 0

def add_exclusion(subreddit_to_exclude):
    if subreddit_to_exclude == None:
        return -1
    if subreddit_to_exclude in EXCLUDED_SUBREDDITS:
        return 1
    EXCLUDED_SUBREDDITS.append(subreddit_to_exclude)
    return 0
    
def remove_exclusion(subreddit_to_include):
    if subreddit_to_include == None:
        return -1
    if subreddit_to_include not in EXCLUDED_SUBREDDITS:
        return 1
    EXCLUDED_SUBREDDITS.remove(subreddit_to_include)
    return 0

def get_report_data(mentions):
    report = {}
    for mention in mentions:
        subr_name = mention.subreddit.display_name
        subr_key = subr_name.lower()
        report[subr_key] = report.get(subr_key, 0) + 1
        if subr_key + "|links" not in report:
            report[subr_key + "|links"] = []
        report[subr_key + "|links"].append(mention.permalink)
        report[subr_key + "|name"] = subr_name
    return report

def print_report(report):
    report_message = "Subreddit|Mentions|Links\n"
    report_message += ":--|--:|:--\n"
    includes_reference = False
    for sub in report:
        if sub not in EXCLUDED_SUBREDDITS:
            includes_reference = True
            break
    if len(report) > 0 and includes_reference: # make sure a non-excluded reference is in the report
        for key, value in report.items():
            if "|links" in key or "|name" in key:
                continue
            if key in EXCLUDED_SUBREDDITS:
                continue
            report_message += report[key + "|name"] + "|" + str(value) + "|"
            linklist = report[key + "|links"]
            i = 1
            for link in linklist:
                report_message += "[" + str(i) + "](" + link + ") "
                i = i + 1
            report_message += "\n"
    else:
        report_message += "None|0|N/A\n"
    report_message += "\n"
    return report_message
    
def standard_message(report, last_time, time, recipient=None, is_special=False):
    if recipient == None:
        recipient_text = 'r/' + config.SUBREDDIT + ' mods'
    else:
        recipient_text = '/u/' + recipient.name
    if is_special:
        special_text = 'special'
    else:
        special_text = 'regular'
    report_message = "Hi " + recipient_text + "!\n\nThis is your " + special_text + " report on references to the subreddit"
    report_message += " throughout Reddit. This does NOT include cross-posts, which are generally handled"
    report_message += " by other means, but it does include direct post or comment linking.\n\n"
    report_message += print_report(report)
    report_message += "This report generated by the Brigade Warning Bot.\n\nTime covered: from "
    report_message += last_time.ctime() + " UTC to " + time.ctime() + " UTC."
    return report_message
    
def reply_status():
    return 0

def reply_status_content(mentions, author, last_time):
    report = get_report_data(mentions)
    message = standard_message(report, last_time, datetime.datetime.utcnow(), author, True)
    message += '\n\nThe current timeframe is ' + str(TIMELAPSE / 60 / 60) + ' hours.'
    message += '\n\nThe current list of excluded subreddits is:\n\n'
    for sub in EXCLUDED_SUBREDDITS:
        message += '* ' + sub + '\n'
    message += '\nPlease note that the bot is not restarting its current cycle, so '
    message += 'you will likely see some of the same references in the next regularly'
    message += ' scheduled notification.'
    return message

def timeframe_updated(timelapse, author, last_time):
    message = 'Hi /u/' + author.name + '!\n\n'
    message += 'The timeframe for the bot has now been updated to '
    message += str(timelapse) + ' hours. If that is less than the '
    message += 'current cycle, a message will be sent immediately.'
    message += ' (NB: Intervening mentions may be lost if the new '
    message += 'timeframe is significantly smaller than the old '
    message += 'one.)\n\nOtherwise, the current cycle will be extended'
    message += ' until the given timeframe has elapsed. For reference,'
    message += ' the current cycle began at ' + last_time.ctime()
    message += ' UTC and the current time is ' + datetime.datetime.utcnow().ctime()
    message += ' UTC.'
    return message

def exclusion_added(exclusion, author):
    message = 'Hi /u/' + author.name + '!\n\n'
    message += 'The list of excluded subreddits has been updated to '
    message += 'include r/' + exclusion + '. If there were mentions '
    message += 'on that subreddit prior to now, they may still be '
    message += 'included in the next report, but starting now, that '
    message += 'subreddit will be ignored.\n\nFor reference, here is'
    message += ' the current list of excluded subreddits:\n\n'
    for sub in EXCLUDED_SUBREDDITS:
        message += '* r/' + sub + '\n'
    return message

def exclusion_removed(inclusion, author):
    message = 'Hi /u/' + author.name + '!\n\n'
    message += 'The list of excluded subreddits has been updated to '
    message += 'remove r/' + inclusion + '. If there were mentions '
    message += 'on that subreddit prior to now, they may not be '
    message += 'included in the next report, but starting now, that '
    message += 'subreddit will be checked.\n\nFor reference, here is'
    message += ' the current list of excluded subreddits:\n\n'
    for sub in EXCLUDED_SUBREDDITS:
        message += '* r/' + sub + '\n'
    return message

def invalid_command(cmd):
    return 'You have attempted to send a command, but the command you sent was invalid. You sent `' + cmd + '`.'

def invalid_params():
    return 'Either you failed to include a required parameter for your command or the parameter you supplied was invalid.'
    
def improper_selection():
    message = 'The subreddit you indicated to exclude is already on the exclusion list,'
    message += ' or the one you indicated to include is not.'
    return message

def handle_message_command(msg):
    # first, get the full list of valid administrators, which includes moderators of the given sub
    # (we do this now instead of during setup so that the mods of a sub can change without us having
    # to restart the bot)
    global reply_msg
    global result
    global r
    global mentions
    global last_time
    result = 0
    reply_msg = ''
    
    for mod in r.subreddit(config.SUBREDDIT).moderator():
        VALID_ADMINS.append(str(mod))
    # if the sender isn't a valid operator, ignore them
    if msg.author not in VALID_ADMINS:
        return
    cmd = msg.subject.split()
    if cmd[0].lower() not in BOT_COMMANDS:
        cmd = msg.body.split()
    # if the command is invalid, report that
    if cmd[0].lower() not in BOT_COMMANDS:
        reply_msg = invalid_command(cmd[0]) + bot_signature()
        msg.reply(reply_msg)
        return
    codeToExec = 'global result; result = ' + switch(BOT_COMMANDS, '-1', cmd[0].lower())
    #print(result)
    exec(codeToExec, globals(), locals())
    if result < 0:
        reply_msg = invalid_params()
    elif result > 0:
        reply_msg = improper_selection()
    else:
        codeToExec = 'global reply_msg; reply_msg = ' + switch(BOT_REPLIES, '-1', cmd[0].lower())
        exec(codeToExec, globals(), locals())
    reply_msg += bot_signature()
    msg.reply(reply_msg)
    return

def subs_and_cmts(subreddit, **kwargs):
    results = []
    results.extend(subreddit.new(**kwargs))
    results.extend(subreddit.comments(**kwargs))
    results.extend(r.inbox.all())
    results.sort(key=lambda post: post.created_utc, reverse=True)
    return results

r = praw.Reddit(user_agent=config.USER_AGENT, client_id=config.CLIENT_ID, client_secret=config.CLIENT_SECRET, username=config.REDDIT_USER, password=config.REDDIT_PW)

mentions = []
last_time = None
posts_evald = []

try:
    while True:
        # get recent posts and comments
        strm = praw.models.util.stream_generator(lambda **kwargs: subs_and_cmts(r.subreddit('all'), **kwargs))
        # check bodies of posts
        #print("Beginning post stream...")
        for post in strm:
            time = datetime.datetime.utcnow()
            if last_time != None:
                timeDelt = time - last_time
                if (timeDelt.total_seconds() > TIMELAPSE): # 12 hours by default
                    #print("Sending report!")
                    post_report = get_report_data(mentions)
                    # send the message
                    report_message = standard_message(post_report, last_time, time)
                    report_message += bot_signature()
                    hour_count = TIMELAPSE / 60 / 60
                    # r.subreddit(config.SUBREDDIT).message(str(hour_count) + ' hour mention report',report_message)
                    r.redditor(config.ADMIN_USER).message(str(hour_count) + ' hour mention report',report_message)
                    # clear the lists
                    mentions.clear()
                    # update the timestamp
                    last_time = time
                    #print("New loop begins: ",last_time.ctime())
            else:
                last_time = time
                #print("Time begins: ",last_time.ctime())
            #print(" - ",post.id)
            if post.id not in posts_evald:
                if isinstance(post,praw.models.Message):
                    handle_message_command(post)
                elif isinstance(post,praw.models.Submission):
                    if "r/" + config.SUBREDDIT in post.selftext.lower():
                        mentions.append(post)
                else:
                    if "r/" + config.SUBREDDIT in post.body.lower():
                        mentions.append(post)
                if isinstance(post,praw.models.Message):
                    post.delete()
                else:
                    posts_evald.append(post.id)
except Exception as e:
    err_msg = str(e) + "\n\n"
    tb = sys.exc_info()[2]
    el = traceback.extract_tb(tb)
    traces = traceback.format_list(el)
    for trace in traces:
        err_msg += "    " + trace + "\n"
    r.redditor(config.ADMIN_USER).message('HELP!',err_msg)