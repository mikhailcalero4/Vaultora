#track actions in a lost or DB, then summarize
#(user, action, resource, ts)
user_activity = [] 

def report_action(user, action, resource):
    user_activity.append((user, action, resource, time.time()))

@app.route("/report")
@role_required('admin')
def activity_report():
    #summarize and format results as HTML or CSV
    return render_template("report.html", activity=user_activity)