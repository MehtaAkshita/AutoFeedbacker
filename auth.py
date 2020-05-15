from flask import Blueprint, render_template,redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from . import db

# from summarizer import Summarizer

import requests
import paralleldots

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))


@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    # create new user with the form data. Hash the password so plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@auth.route('/summarise')
def summarise():
    return render_template('summarise.html')    


@auth.route('/summarise',methods=['POST'])
def summarise_done():
	# model = Summarizer('distilbert-base-uncased')
	text=request.form.get('text')
	# text="'''"+text+"'''"
	# resp = model(text)
	r = requests.post("https://api.deepai.org/api/summarization", data={'text': text,},headers={'api-key': '4660d33e-0b5d-4835-8236-9c30b0b72191'})
	print(r.json())
	resp=r.json()['output']
	print(f'Summary: {resp}')
	return render_template('summarise.html',summary=resp,text=text)    



@auth.route('/intent')
def intent():
    return render_template('intent.html')    

@auth.route('/intent',methods=['POST'])
def intent_done():
	# model = Summarizer('distilbert-base-uncased')
	text=request.form.get('text')
	# text="'''"+text+"'''"
	# resp = model(text)
	paralleldots.set_api_key("7acE4lEzKSjWWzt6o7tYBzX0RdetEFM0jphV39HTHXg")
	resp=paralleldots.intent(text)
	news=resp['intent']['news']
	query=resp['intent']['query']
	spam=resp['intent']['spam']
	marketing=resp['intent']['marketing']
	feedback=resp['intent']['feedback']
	ans="News : "+str(news*100)+" % \n"+"Query : "+str(query*100)+" % \n"+"Spam : "+str(spam*100)+" % \n"+"Marketing : "+str(marketing*100)+" % \n"+"Feedback : "+str(feedback*100)+" %"
	print(f'Summary: {ans}')
	return render_template('intent.html',summary=ans,text=text)     


@auth.route('/sentiment')
def sentiment():
    return render_template('sentiment.html') 

@auth.route('/sentiment',methods=['POST'])
def sentiment_done():
	# model = Summarizer('distilbert-base-uncased')
	text=request.form.get('text')
	# text="'''"+text+"'''"
	# resp = model(text)
	r = requests.post("https://api.deepai.org/api/sentiment-analysis", data={'text': text,},headers={'api-key': '4660d33e-0b5d-4835-8236-9c30b0b72191'})
	print(r.json())
	resp=r.json()['output']
	positive=resp.count('Positive')
	neutral=resp.count('Neutral')
	negative=resp.count('Negative')
	total=positive+neutral+negative
	ans="Positive : "+str((positive/total)*100)+" % \n"+"Negative : "+str((negative/total)*100)+" % \n"+"Neutral : "+str((neutral/total)*100)+" %"
	print(f'Summary: {ans}')
	return render_template('sentiment.html',summary=ans,text=text)    


#TEXT SUMMARISER
# def read_article(filedata):
#     # file = open(file_name, "r")
#     # filedata = file.readlines()
#     article = filedata[0].split(". ")
#     sentences = []

#     for sentence in article:
#         print(sentence)
#         sentences.append(sentence.replace("[^a-zA-Z]", " ").split(" "))
#     sentences.pop() 
    
#     return sentences

# def sentence_similarity(sent1, sent2, stopwords=None):
#     if stopwords is None:
#         stopwords = []
 
#     sent1 = [w.lower() for w in sent1]
#     sent2 = [w.lower() for w in sent2]
 
#     all_words = list(set(sent1 + sent2))
 
#     vector1 = [0] * len(all_words)
#     vector2 = [0] * len(all_words)
 
#     # build the vector for the first sentence
#     for w in sent1:
#         if w in stopwords:
#             continue
#         vector1[all_words.index(w)] += 1
 
#     # build the vector for the second sentence
#     for w in sent2:
#         if w in stopwords:
#             continue
#         vector2[all_words.index(w)] += 1
 
#     return 1 - cosine_distance(vector1, vector2)
 
# def build_similarity_matrix(sentences, stop_words):
#     # Create an empty similarity matrix
#     similarity_matrix = np.zeros((len(sentences), len(sentences)))
 
#     for idx1 in range(len(sentences)):
#         for idx2 in range(len(sentences)):
#             if idx1 == idx2: #ignore if both are same sentences
#                 continue 
#             similarity_matrix[idx1][idx2] = sentence_similarity(sentences[idx1], sentences[idx2], stop_words)

#     return similarity_matrix


# def generate_summary(file_name, top_n=5):
#     stop_words = stopwords.words('english')
#     summarize_text = []

#     # Step 1 - Read text anc split it
#     sentences =  read_article(file_name)

#     # Step 2 - Generate Similary Martix across sentences
#     sentence_similarity_martix = build_similarity_matrix(sentences, stop_words)

#     # Step 3 - Rank sentences in similarity martix
#     sentence_similarity_graph = nx.from_numpy_array(sentence_similarity_martix)
#     scores = nx.pagerank(sentence_similarity_graph)

#     # Step 4 - Sort the rank and pick top sentences
#     ranked_sentence = sorted(((scores[i],s) for i,s in enumerate(sentences)), reverse=True)    
#     print("Indexes of top ranked_sentence order are ", ranked_sentence)    

#     for i in range(top_n):
#       summarize_text.append(" ".join(ranked_sentence[i][1]))

#     # Step 5 - Offcourse, output the summarize texr
#     print("Summarize Text: \n", ". ".join(summarize_text))

# # let's begin

