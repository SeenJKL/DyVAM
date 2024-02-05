from flask import Flask, render_template, request, redirect, url_for
from flask_pymongo import PyMongo

app = Flask(__name__)

# MongoDB configuration
app.config['MONGO_URI'] = 'mongodb://localhost:27017/DyVAM_Database'
mongo = PyMongo(app)

@app.route('/')
def index():
    # Access the "dyvam_collection" collection in MongoDB
    collection = mongo.db.dyvam_collection

    # Get distinct @host values
    distinct_hosts = collection.distinct('@host')

    # Create a pipeline to find the newest 'generated time' for each @host
    pipeline = [
        {"$sort": {"generated_time": -1}},
        {"$group": {"_id": "$@host", "latest_time": {"$first": "$generated_time"}}}
    ]

    # Aggregate the data using the pipeline
    result = list(collection.aggregate(pipeline))

    # Create a dictionary to map @host to the corresponding latest_time
    host_time_mapping = {entry['_id']: entry['latest_time'] for entry in result}

    # Pass the data to the template
    return render_template('index.html', distinct_hosts=distinct_hosts, host_time_mapping=host_time_mapping)

@app.route('/host/<host>')
def host_page(host):
    # Access the "dyvam_collection" collection in MongoDB
    collection = mongo.db.dyvam_collection

    # Query the collection for documents where "@host" is the specified host
    query = {"@host": host}

    # Sort documents by 'generated time' in descending order and retrieve the first document
    document = collection.find_one(query, sort=[("generated_time", -1)])

    # Pass the data to the template
    return render_template('host_page.html', host=host, document=document)

@app.route('/acknowledge', methods=['POST'])
def acknowledge_alerts():
    if request.method == 'POST':
        selected_alerts = request.form.getlist('acknowledge_alerts')
        host = request.form.get('host')
        existing_document = mongo.db.dyvam_collection.find_one({'@host': host})
        for alert_key in existing_document['alerts']:
            is_checked = alert_key in selected_alerts
            update_query = {
                '@host': host,
                f'alerts.{alert_key}.acknowledge': is_checked,
            }
            mongo.db.dyvam_collection.update_one({'@host': host}, {'$set': update_query})
    updated_document = mongo.db.dyvam_collection.find_one({'@host': host})
    return render_template('host_page.html', host=host, document=updated_document)


if __name__ == '__main__':
    app.run(debug=True)
