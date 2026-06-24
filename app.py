import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler

def preprocess_data(input_data, pmap, fmap, features, sc):
    """Preprocesses the input data."""
    input_df = pd.DataFrame([input_data], columns=features)
    input_df['protocol_type'] = input_df['protocol_type'].map(pmap)
    input_df['flag'] = input_df['flag'].map(fmap)
    input_df = input_df[features]
    input_data_scaled = sc.transform(input_df)
    return input_data_scaled.reshape((-1,30,1)) # Reshape for CNN
def predict_attack(preprocessed_data, cnn_model):
    """Predicts the attack type using the CNN model."""
    prediction = cnn_model.predict(preprocessed_data)
    amap = {0: 'dos', 1: 'normal', 2: 'probe', 3: 'r2l', 4: 'u2r'}
    predicted_attack_type = amap[np.argmax(prediction)]
    return predicted_attack_type

def network_attack_pipeline(input_data, cnn_model, pmap, fmap, features, sc):
    """
    A pipeline for predicting network attacks.

    Args:
        input_data (dict): Input data dictionary.
        cnn_model (keras.Model): Trained CNN model.
        pmap (dict): Mapping for protocol_type.
        fmap (dict): Mapping for flag.
        features (list): List of features used in training.
        sc (MinMaxScaler): Scaler object.

    Returns:
        str: Predicted attack type.
    """
    preprocessed_data = preprocess_data(input_data, pmap, fmap, features, sc)
    predicted_attack = predict_attack(preprocessed_data, cnn_model)
    return predicted_attack

pmap = {'icmp': 0, 'tcp': 1, 'udp': 2}
fmap = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5, 'S1': 6, 'S2': 7, 'RSTOS0': 8, 'S3': 9, 'OTH': 10}
features = ['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land',
       'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
       'num_compromised', 'root_shell', 'su_attempted', 'num_file_creations',
       'num_shells', 'num_access_files', 'is_guest_login', 'count',
       'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
       'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
       'dst_host_srv_count', 'dst_host_diff_srv_rate',
       'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate']

import tensorflow as tf
import joblib
import pickle
cnn_model = tf.keras.models.load_model("cnn_model.h5")


# Load the MinMaxScaler
scaler = joblib.load("scaler.pkl")


# Now this section in for frontend....
import streamlit as st
st.caption('Input must be in given sequence: ')
st.caption(features)
st.caption("Eg: '0, 1,0,181,5450,0,0,0,0,0,1,0,0,0,0,0,0,0,8,8,0,0,1,0,0,9,9,0,0.11,0'")
input=st.text_input("Enter the input with comma Seprated value: ")
listVal=input.split(',')
def predict():
    inputList=[]
    inputList.append((int)(listVal[0]))
    inputList.append(listVal[1])
    inputList.append(listVal[2])
    inputList.append((int)(listVal[3]))
    inputList.append((int)(listVal[4]))
    inputList.append((int)(listVal[5]))
    inputList.append((int)(listVal[6]))
    inputList.append((int)(listVal[7]))
    inputList.append((int)(listVal[8]))
    inputList.append((int)(listVal[9]))
    inputList.append((int)(listVal[10]))
    inputList.append((int)(listVal[11]))
    inputList.append((int)(listVal[12]))
    inputList.append((int)(listVal[13]))
    inputList.append((int)(listVal[14]))
    inputList.append((int)(listVal[15]))
    inputList.append((int)(listVal[16]))
    inputList.append((int)(listVal[17]))
    inputList.append((int)(listVal[18]))
    inputList.append((int)(listVal[19]))
    inputList.append((float)(listVal[20]))
    inputList.append((float)(listVal[21]))
    inputList.append((float)(listVal[22]))
    inputList.append((float)(listVal[23]))
    inputList.append((float)(listVal[24]))
    inputList.append((int)(listVal[25]))
    inputList.append((int)(listVal[26]))
    inputList.append((float)(listVal[27]))
    inputList.append((float)(listVal[28]))
    inputList.append((float)(listVal[29]))
    ans=''
    try:
        ans=network_attack_pipeline(inputList,cnn_model, pmap, fmap, features, scaler)
    except:
        return "Input is not in valid form:"   
    return ans
    
if(st.button('Predict')):
    st.title(predict())


input2 =st.number_input("Enter the input between(0-494021)",step=1)             
def predict1():
    df=pd.read_csv('validation.csv')
    try:
        x=df.iloc[input2,:-1]
        lb=df.iloc[input2,-1]
        st.title(f"Labeled as: {lb.upper()}")
    except:
        st.title("There is some issue try on another value...")
        
    print(df.iloc[input2,-1])
    try:
        res=network_attack_pipeline(x,cnn_model, pmap, fmap, features, scaler)
        st.title(f"Predicted as: {res.upper()}")
    except:
        st.title("There is some issue try on another value...")

if(st.button('Validate')):
    predict1()





