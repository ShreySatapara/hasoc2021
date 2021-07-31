from flask import Flask, request, Response, redirect, url_for, json, make_response, jsonify
import pymongo
import jwt
import hashlib
from flask_bcrypt import Bcrypt
from functools import wraps
from datetime import datetime, timedelta
from flask_cors import cross_origin, CORS
import urllib
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['CORS_HEADERS'] = 'application/json'
CORS(app)
## AUTH token wrap #########################
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'Token is invalid !!'}), 401
        return  f(*args, **kwargs)
    return decorated

def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            if(data['isadmin']):
                pass
            else:
                return jsonify({
                'message' : 'Token is invalid !!'
            }), 401    
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        return  f(*args, **kwargs)
    return decorated


########################################### DB config ###########################################
try:
    mongo = pymongo.MongoClient("")
    db = mongo.hasoc
    print('\n\n' + '#'*10 + '\n\nSUCCESS\n\n' + '#'*10)
    mongo.server_info()
except Exception as ex:
    print('\n\n\n*********************************\n\n\n')
    print(ex)
    print('\n\n\n*********************************\n\n\n')
#################################################################################################
### GET POST STORY  #####################################################################################################################
@app.route('/admin/story', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@admin_token_required 
def story():
    try:
        if request.method == 'POST':
            story = request.get_json()
            story = story['story']
            if(story!='' and type(story)==str):
                d = db.stories.insert_one({"_id":story})
                return Response(response=json.dumps({'message': 'data submitted successfully'}), status=200, mimetype="application/json")
            else:
                return Response(response=json.dumps({'message': 'Bad Request'}), status=400, mimetype="application/json")    
        else:
            count_required = request.args.get("count_required")
            stories = list(db.stories.find())
            s  = dict()
            s['stories'] = stories
            if(count_required!=None):
                if(int(count_required)):
                    story_count = {}
                    for index in stories:
                        story_count[index['_id']] = db.tweets.count_documents({'story':index['_id']})
                    s['count'] = story_count
            if(len(stories)>0):
                return Response(response=json.dumps(s), status=200, mimetype="application/json")
            return Response(response=json.dumps({'message':'no data found'}), status=404, mimetype="application/json")
    except pymongo.errors.DuplicateKeyError:
        return Response(
            response=json.dumps({'message':'duplicate entry'}),status=403,mimetype='application/json')
    except Exception as Ex:
        print('\n\n\n*********************************')
        print(Ex)
        print('*********************************\n\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")
#####################################################################################################################################
## LOGIN ######################
@app.route('/login', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
def login():
    if request.method=='POST':
        form_data = request.get_json()
        name = form_data['name']
        password = form_data['password']
        isAdmin = form_data['isadmin']
        if(name!='' and password!=''):
            data = list(db.users.find({'_id':name}))
            if(len(data)==0):
                return Response(status=404, response=json.dumps({'message':'user does not exist'}), mimetype='application/json')
            else:
                data = data[0]
                db_password_hash = data['password_hash']
                if(bcrypt.check_password_hash(db_password_hash, password)):
                    if(data['adminAccess']):
                        token = jwt.encode({
                            'uname': name,
                            'isadmin':data['adminAccess'],
                            'exp' : datetime.utcnow() + timedelta(hours = 4)}, app.config['SECRET_KEY']) 
                        return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
                    else:
                        if(isAdmin):
                            return Response(status=401, response=json.dumps({'message':'invalid user request'}), mimetype='application/json')
                        else:
                            token = jwt.encode({
                                'uname': name,
                                'isadmin':data['adminAccess'],
                                'exp' : datetime.utcnow() + timedelta(hours = 4)}, app.config['SECRET_KEY']) 
                            return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
                else:
                    return Response(status=402, response=json.dumps({'message':'Invalid password'}), mimetype='application/json')
        else:
            return Response(status=400, response=json.dumps({'message':'Bad request'}), mimetype='application/json')
    else:
        return 'hello wordl!!!'

## CHANGE PASSWORD ###########################################
@app.route('/change_password', methods=['POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@token_required
def change_password():
    try:
        if request.method == 'POST':
            data = request.get_json()
            uname = data['name']
            password = data['password']
            new_password = data['new_password']
            data = list(db.users.find({'_id':uname}))
            if(len(data)>0):    
                data = data[0]
                db_password_hash = data['password_hash']
                if(bcrypt.check_password_hash(db_password_hash, password)):
                    password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    db.users.update_one({'_id':uname},{'$set':{'password_hash':password_hash}})
                    return Response(status=200, response=json.dumps({'message':'password updated successfully'}), mimetype='application/json')
                else:
                    return Response(status=402, response=json.dumps({'message':'invalid password'}), mimetype='application/json')
            else:
                return Response(status=404, response=json.dumps({'message':'invalid user'}),mimetype='application/json')
    except Exception as Ex:
        print('\n\n\n*********************************')
        print(Ex)
        print('*********************************\n\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")

##############################################################
########################################################################################################################################
## ADD TWEET ###########################################################################################################################
@app.route('/admin/add_tweet', methods=['POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@admin_token_required
def add_tweet():
    try:
        if request.method == 'POST':
            f = request.files.getlist('files')
            json_files = []
            story = request.form.get('story_name')
            for json_file in f:
                json_data = json_file.read()
                data = json.loads(json_data)
                data['story'] = story
                data['assigned_to'] = [] 
                data['annotated_by'] = []
                data['_id'] = data['tweet_id']
                json_files.append(data)
            d = db.tweets.insert_many(json_files)
            return Response(response=json.dumps({'message': 'data submitted successfully'}), status=200, mimetype="application/json")
    except Exception as Ex:
        print('\n\n\n*********************************')
        print(Ex)
        print('*********************************\n\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")
########################################################################################################################################
##### GET POST USER ###########################################################################################################
def return_user_list():
    users = list(db.users.find({},{'email':1,'adminAccess':1}))
    return users


@app.route('/admin/user', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@admin_token_required
def user():
    try:
        if request.method == 'POST':
            data = request.get_json()
            name = data['name']
            email = data['email']
            password = data['password']
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            isadmin = data['isadmin']
            d = db.users.insert_one({'_id':name,'email':email,'password_hash':password_hash,"adminAccess":isadmin})
            return Response(
                response=json.dumps({'message': 'User created successfully'}), status=200, mimetype="application/json")
        else:
            usrs = dict()
            u = return_user_list()
            count_by_user = {}
            for user in u:
                name = user['_id']
                assigned_count = db.tweets.count_documents({'assigned_to':name})
                annotated_count = db.tweets.count_documents({'annotated_by':name})
                user['assigned'] = assigned_count
                user['annotated'] = annotated_count
            usrs['users'] = u
            return usrs
    except pymongo.errors.DuplicateKeyError:
        return Response(
            response=json.dumps({'message':'duplicate username'}),status=403,mimetype='application/json')
    except Exception as Ex:
        print('\n\n\n*********************************')
        print(Ex)
        print('*********************************\n\n\n')
        return Response(
            response=json.dumps({'message': Ex}), status=500, mimetype="application/json")


############ GET TWEET DATA FOR DASHBOARD ################################

@app.route('/api/index', methods=['GET','POST'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@admin_token_required
def index_data():
    try:
        if request.method == 'POST':
            data = request.get_json()
            user_list = data['users_assigned']
            arr = []
            tweet_id = data['tweet_id']
            for user in user_list:
                db.tweets.update_one({'_id':tweet_id},{'$set':{user:{}},'$push':{'assigned_to':user}})
            return Response(status=200, response = json.dumps({'message':'assigned successfully'}), mimetype='application/json') 
        else:
            story_name = request.args.get('story_name')
            if(story_name==None or story_name=='all'):
                data = list(db.tweets.find({},{'tweet_id':1,'tweet':1,'assigned_to':1,'story':1,'annotated_by':1}))
                if(len(data)>0):
                    d = {}
                    d['tweet_data'] = data
                    users = return_user_list()
                    d['users'] = users
                    return Response(status=200, response = json.dumps(d), mimetype='application/json') 
                else:
                    return Response(status=404, response=json.dumps({'message':'data found'}),mimetype='application/json')
            else:
                data = list(db.tweets.find({'story':story_name},{'tweet_id':1,'tweet':1,'assigned_to':1,'story':1, 'annotated_by':1}))
                if(len(data)>0):
                    d = {}
                    d['tweet_data'] = data
                    users = return_user_list()
                    d['users'] = users
                    return Response(
                        status=200, response = json.dumps(d), mimetype='application/json') 
                else:
                    return Response(status=404, response=json.dumps({'message':'data found'}),mimetype='application/json')
    except Exception as Ex:
        return Response(status=500, response = json.dumps({'message':Ex}), mimetype='application/json') 
        
############################################################################################################################
## Tweets by user ##########################################################################################################
@app.route('/api/tweet_by_user', methods=['GET'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@token_required
def get_tweets_by_user():
    try:
        name = request.args.get("name")
        if(name!=None):
            data = list(db.tweets.find({'assigned_to':name},{'story':1,'tweet_id':1,'tweet':1,'annotated_by':1,'assigned_to':1}))
            return Response(status=200, response=json.dumps({'data':data}), mimetype='application/json')
        return Response(status=400, response=json.dumps({'message':'invalid input'}), mimetype='application/json')
    except Exception as Ex:
        return Response(status=500, response={'message':'internal server error'}, mimetype='application/json')
########################################################################################################################################
###################### Tweet_by_user ##########################################################################################################
@app.route('/tweet_for_annotation/<name>/<tweet_id>', methods=['GET','POST','OPTIONS'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@token_required
def tweet_for_annotation(name=None, tweet_id=None):
    try:
        if request.method =='POST':
            label_data = request.get_json()
            print(label_data)
            id = label_data['id']
            label = label_data['label']
            print(tweet_id)
            print(len(list(db.tweets.find({'_id':tweet_id,'annotated_by':name}))))
            if(len(list(db.tweets.find({'_id':tweet_id,'annotated_by':name})))==1):
                db.tweets.update_one({'_id':tweet_id,'assigned_to':name},{'$set':{name+'.'+id:label}})
            else:
                db.tweets.update_one({'_id':tweet_id,'assigned_to':name},{'$push':{'annotated_by':name},'$set':{name:{id:label}}})
            return Response(status=200, response=json.dumps({'message':"labels stored successfully"}), mimetype='application/json')
        else:
            if(name!=None):
                if(tweet_id=="undefined"):
                    data = list(db.tweets.find({'assigned_to':name}))
                else:
                    data = list(db.tweets.find({"_id":tweet_id,"assigned_to":name}))
                if(len(data)==0):
                    return Response(status=404,response=json.dumps({'message':'data unavailable'}), mimetype='application/json')
                data = data[0]
                d = {}
                d['tweet'] = data
                return Response(
                    status=200, response=json.dumps(d), mimetype='application/json')
    except Exception as Ex:
        print(Ex)
        return Response(status=500, response = json.dumps({"message":'invalid request'}), mimetype='application/json')

########################################################################################################################################
########### Dashboard statatics ##########################################################################
@app.route('/admin/dashboard', methods=['GET','POST','OPTIONS'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@admin_token_required
def get_dashboard_statatics():
    try:
        data = list(db.tweets.find())
        storywise_count = dict()
        userwise_count = dict()
        total_tweets_story = 0
        total_tweets_annotated = 0
        storywise_tweets_count = list(db.tweets.aggregate([{'$group':{'_id':'$story','tweets_count':{'$sum':'$tweets_count'}}}]))
        total_annotated_count = {'by_one':0,'by_two':0,'by_three':0}
        total = 0
        storywise_count = dict()
        for story in storywise_tweets_count:
            story_name = story['_id']
            if(story_name not in storywise_count):
                storywise_count[story_name] = {}
            storywise_count[story_name]['no_of_status'] = db.tweets.count_documents({'story':story_name})
            storywise_count[story_name]['tweets_count'] = story['tweets_count']
            total_tweets_story += story['tweets_count']
            storywise_count[story_name]['annotated_by_one'] = db.tweets.count_documents({'story':story_name,'annotated_by.0':{'$exists':True}})
            storywise_count[story_name]['annotated_by_two'] = db.tweets.count_documents({'story':story_name,'annotated_by.1':{'$exists':True}})
            storywise_count[story_name]['annotated_by_three'] = db.tweets.count_documents({'story':story_name,'annotated_by.2':{'$exists':True}})
            total_annotated_count['by_one'] += storywise_count[story_name]['annotated_by_one']
            total_annotated_count['by_two'] += storywise_count[story_name]['annotated_by_two']
            total_annotated_count['by_three'] += storywise_count[story_name]['annotated_by_three']
            total += storywise_count[story_name]['no_of_status'] 
        users = list(db.users.find({},{'_id':1}))
        userwise_count['assigned_total'] = 0
        userwise_count['annotated_total'] = 0
        for user in users:
            user = user['_id']
            if(user not in userwise_count):
                userwise_count[user] = {}
            userwise_count[user]['assigned'] = db.tweets.count_documents({'assigned_to':user})
            userwise_count[user]['annotated'] = db.tweets.count_documents({'annotated_by':user})
            userwise_count['assigned_total'] += userwise_count[user]['assigned']
            userwise_count['annotated_total'] += userwise_count[user]['annotated']
            if('tweets_annotated_count' not in userwise_count[user]):
                userwise_count[user]['tweets_annotated_count'] = 0
            #storywise_annotated_tweets_count = {}   
            for tweet_data in data:
                if(user in tweet_data['annotated_by']):
                    userwise_count[user]['tweets_annotated_count'] += len(tweet_data[user].keys())
                    total_tweets_annotated += len(tweet_data[user].keys())
        return {'storywise_count':storywise_count,'userwise_count':userwise_count,'total_annotated_count':total_annotated_count,'total_status':total, 'total_tweets_story':total_tweets_story,'total_tweets_annotated':total_tweets_annotated}
    except Exception as Ex:
        print('#'*10)
        print(Ex)
        print('#'*10)
        return Ex
###############################################################################
############## third annotation
@app.route('/tweet_for_third_annotation/<name>/<tweet_id>', methods=['GET','POST','OPTIONS'])
@cross_origin(origin='*',headers=['Content- Type','Authorization'])
@token_required
def tweet_for_third_annotation(name=None, tweet_id=None):
    try:
        if request.method =='POST':
            label_data = request.get_json()
            print(label_data)
            id = label_data['id']
            label = label_data['label']
            print(tweet_id)
            print(len(list(db.tweets.find({'_id':tweet_id,'annotated_by':name}))))
            if(len(list(db.tweets.find({'_id':tweet_id,'annotated_by':name})))==1):
                db.tweets.update_one({'_id':tweet_id,'assigned_to':name},{'$set':{name+'.'+id:label}})
            else:
                db.tweets.update_one({'_id':tweet_id,'assigned_to':name},{'$push':{'annotated_by':name},'$set':{name:{id:label}}})
            return Response(status=200, response=json.dumps({'message':"labels stored successfully"}), mimetype='application/json')
        else:
            if(name!=None):
                if(tweet_id=="undefined"):
                    data = list(db.tweets.find({'assigned_to.2':name}))
                else:
                    data = list(db.tweets.find({"_id":tweet_id,"assigned_to.2":name}))
                if(len(data)==0):
                    return Response(status=404,response=json.dumps({'message':'data unavailable'}), mimetype='application/json')
                data = data[0]
                d = {}
                d['tweet'] = data
                return Response(
                    status=200, response=json.dumps(d), mimetype='application/json')
    except Exception as Ex:
        print(Ex)
        return Response(status=500, response = json.dumps({"message":'invalid request'}), mimetype='application/json')



if __name__=="__main__":
    app.run(debug=True)