import streamlit as st 
import numpy as np 
import matplotlib.pyplot as plt
from sklearn import datasets
from sklearn.model_selection import train_test_split
import tensorflow as tf
import keras
from benchmark import kitsune
from keras.utils import np_utils
from sklearn.decomposition import PCA
from sklearn.neighbors import KNeighborsClassifier
from benchmark import kdd_benchmark
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score
from sklearn.metrics import roc_auc_score
from sklearn.metrics import classification_report
import pandas as pd
import sklearn
from pandas import ExcelFile
from sklearn.metrics import confusion_matrix
from sklearn import preprocessing
from sklearn.metrics import accuracy_score
import benchmark
from sklearn.feature_extraction.text import CountVectorizer
from cleverhans.tf2.attacks.projected_gradient_descent import projected_gradient_descent
from cleverhans.tf2.attacks.fast_gradient_method import fast_gradient_method
from cleverhans.tf2.attacks.momentum_iterative_method import momentum_iterative_method
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import KFold
import numpy as np
import matplotlib.pyplot as plt
 

Num_Column = [ 'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment',
                'urgent', 'hot', 'num_failed_logins', 'num_compromised',
                'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                'num_shells', 'num_access_files', 'num_outbound_cmds', 'count',
                'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
                'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
                'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']


def create_tf_model(input_size, num_of_class):
    model_kddcup = tf.keras.Sequential([
        tf.keras.layers.Dense(200, input_dim=input_size, activation=tf.nn.relu),
        tf.keras.layers.Dense(500, activation=tf.nn.relu),
        tf.keras.layers.Dense(200, activation=tf.nn.relu),
        tf.keras.layers.Dense(num_of_class),
        tf.keras.layers.Activation(tf.nn.softmax)
        ])
    model_kddcup.compile(loss='categorical_crossentropy',
                         optimizer='adam',
                         metrics=['accuracy'])
    return model_kddcup  


def gen_tf2_fgsm_attack(org_model, x_test, ep):
   
    logits_model = tf.keras.Model(org_model.input, org_model.layers[-1].output)
    epsilon = ep
    adv_fgsm_x = fast_gradient_method(logits_model,
                                      x_test,
                                      epsilon,
                                      np.inf,
                                      targeted=False)
    return adv_fgsm_x


def gen_tf2_mim(org_model, x_test, ep):
   
    logits_model = tf.keras.Model(org_model.input, org_model.layers[-1].output)

    epsilon = ep
    adv_mim_x = momentum_iterative_method(logits_model,
                                          x_test,
                                          epsilon,
                                          eps_iter= 0.06,
                                          nb_iter=100,
                                          norm=np.inf,
                                          targeted=False)
    return adv_mim_x




def gen_tf2_projected_gradient_descent(org_model, x_test, ep):
   
    logits_model = tf.keras.Model(org_model.input, org_model.layers[-1].output)

    adv_pgd_x =projected_gradient_descent(model_fn=logits_model,
    x=x_test,
    eps=ep,
    eps_iter=0.1,
    nb_iter=100,
    norm=np.inf,
    loss_fn=None,
    clip_min=None,
    clip_max=None,
    y=None,
    targeted=False,
    rand_init=None,
    rand_minmax=None,
    sanity_checks=False)
   
    return adv_pgd_x

def get_dataset(name):
    data = None
    if name == 'KDDCup':
        
        data= kdd_benchmark()
        
    elif name == 'Kitsune':
        
        data= kitsune()
    x=data
    y=data.label    
    return x,y


def classi(tf):
    

    if tf=='Decision Tree':
        classifier = DecisionTreeClassifier(criterion = 'entropy', random_state = 0)
        
    elif tf=='K-Nearest Neighbor':
        classifier = KNeighborsClassifier(n_neighbors = 10, metric = 'minkowski', p = 2)
       
    elif tf=='Naive Bayes':
        classifier = GaussianNB()
       
    return classifier

def attacks(name, model, X_test, ep):
    if name == 'Fast Gradient Sign Method':
        
        adv = gen_tf2_fgsm_attack(model, X_test, ep)
        
    elif name == 'Momentum Iterative Method':
    
        adv = gen_tf2_mim(model, X_test, ep)

    elif name=='Projected Gradient Descent':
        
        adv = gen_tf2_projected_gradient_descent(model, X_test, ep)
        
    return adv


def targetedattacks(name, model, X_test_np_onlyattacks, ep):
    
    if name == 'Targeted Fast Gradient Sign Method':
        
        adv = gen_tf2_fgsm_attack(model, X_test_np_onlyattacks, ep)
        
    elif name == 'Targeted Momentum Iterative Method':
    
        adv = gen_tf2_mim(model, X_test_np_onlyattacks, ep)

    elif name=='Targeted Projected Gradient Descent':
        
        adv = gen_tf2_projected_gradient_descent(model, X_test_np_onlyattacks, ep)
        
    return adv

def attackclassi(classifier,X_adv,tf):
    
    if tf=='KNN':
      
        y_prediction = classifier.predict_proba(X_adv)
        y_pred = np.argmax(y_prediction ,axis=1)


    elif tf=='Decision Tree':
       
        y_prediction = classifier.predict_proba(X_adv)
        y_pred = np.argmax(y_prediction ,axis=1)

    elif tf=='Naive Bayes':
      
       
        y_prediction = classifier.predict_proba(X_adv)
        y_pred = np.argmax(y_prediction ,axis=1)
    return y_pred




st.title('Detection and Prevention Of Machine Learning Attacks in Adversarial Setting')

# st.write("""
# # Attack Classification
# """)

dataset_name = st.sidebar.selectbox(
    'Select Dataset',
    ('KDDCup', 'Kitsune')
)

st.write(f"## {dataset_name} Dataset")

classifier_name = st.sidebar.selectbox(
    'Select classifier',
    ('K-Nearest Neighbor', 'Decision Tree', 'Naive Bayes')
)
 
 
attacks_name = st.sidebar.selectbox(
    'Select Attack',
    ('Fast Gradient Sign Method', 'Momentum Iterative Method', 'Projected Gradient Descent')
)

targeted_attacks_name = st.sidebar.selectbox(
    'Select Attack',
    ('Targeted Fast Gradient Sign Method', 'Targeted Momentum Iterative Method', 'Targeted Projected Gradient Descent')
)

epsilon_val = st.sidebar.slider('Select Epsilon Value', min_value=0.0, max_value=1.0, value=0.3, step=0.1)

# attacks_classification = st.sidebar.selectbox(
#     'Select Attack Classifier',
#     ('KNN', 'Decision Tree','Naive Bayes')
# )
    
np_x,np_y=get_dataset(dataset_name)
# np_y=x.iloc[:,-1]
np_x=np_x.iloc[:,:-1]
# X, y = get_dataset(dataset_name)

#np_y = sc_y.transform(np_y)
print("                               ")
 
st.write('Shape of dataset:', np_x.shape)
st.write('number of classes:', len(np.unique(np_y)))

# np_x = np_x.to_numpy()
# np_y = np_y.to_numpy()

# st.write('Shape of y:', np_y.shape)

df_xx = pd.DataFrame(np_x, columns = Num_Column)
df_yy = pd.DataFrame(np_y, columns = ['label'])

X_train, X_test, y_train, y_test = train_test_split(df_xx, df_yy, \
                                                       test_size=0.2)
    
#output of train test split is n dataframe therefore we will first assign it to variables then convert it to numpy. This is 
# done for adversarial training because we need dataframe for concatenation

X_train_df = X_train
X_test_df = X_test
y_train_df = y_train
y_test_df = y_test

# onehoty_train_df = y_train
# onehoty_test_df = y_test


X_test_adv = X_test
# y_test_adv = y_test


X_test_adv_tar = X_test
# y_test_adv_tar = y_test

# st.write('Shape of ytraindf:', y_train_df.shape)
# st.write('Shape of ytrain:', y_train.shape)


encoder = OneHotEncoder(handle_unknown='ignore')
encoder_df = pd.DataFrame(encoder.fit_transform(y_train_df).toarray())
encoder_df_test = pd.DataFrame(encoder.fit_transform(y_test_df).toarray())

X_train = X_train.to_numpy()
X_test = X_test.to_numpy()
y_train = y_train.to_numpy()
y_test = y_test.to_numpy()


classifier = classi(classifier_name)

# if classifier_name=='ANN':
    
model= create_tf_model(np_x.shape[1],len(np.unique(np_y)))
    
st.success("MLP Model Created")
    
one_hot_ytrain = np_utils.to_categorical(y_train)
one_hot_ytest = np_utils.to_categorical(y_test)
history = model.fit(X_train, one_hot_ytrain, epochs=5,
                        batch_size=50000, verbose=0,
                        validation_split=0.3)

st.success("MLP Model Trained")




XX_test_df = pd.DataFrame(X_test)
yy_test_df = pd.DataFrame(y_test , columns=['Label'])
    
result = pd.concat([XX_test_df, yy_test_df], axis=1)

# separate all rows with noraml packet and all rows with malicious packet
cond_ = (result.Label != 1)
condNorm_ = (result.Label == 1)
normal_removed= result[cond_]
normal_data= result[condNorm_]


X_test_df_onlynormal = normal_data.drop(["Label"], axis=1)
y_test_df_onlynormal = normal_data.drop(normal_data.iloc[:,:-1], inplace = False, axis = 1)


X_test_df_onlyattacks = normal_removed.drop(["Label"], axis=1)
y_test_df_onlyattacks = normal_removed.drop(normal_removed.iloc[:,:-1], inplace = False, axis = 1)

X_test_np_onlyattacks = X_test_df_onlyattacks.to_numpy()
y_test_np_onlyattacks = y_test_df_onlyattacks.to_numpy()


adv_attack=attacks(attacks_name, model, X_test, epsilon_val)

adv_targeted = targetedattacks(targeted_attacks_name, model, X_test_np_onlyattacks, epsilon_val)

X_test_df_onlyattacks[:] = adv_targeted.numpy()
    
x_Both = [X_test_df_onlyattacks, X_test_df_onlynormal]
X_test_df_both = pd.concat(x_Both)
X_test_df_both.sort_index(inplace=True)

X_adv_tar = X_test_df_both

X_adv = adv_attack


y_prediction_model=model.predict(X_test)
y_pred_model=np.argmax(y_prediction_model,axis=1)


y_prediction_attack_model = model.predict(X_adv)
y_pred_attack_model=np.argmax(y_prediction_attack_model,axis=1)
y_prediction_target_model = model.predict(X_adv_tar)
y_pred_target_model=np.argmax(y_prediction_target_model,axis=1)


    
model_auc = roc_auc_score(y_test,y_prediction_model, multi_class='ovr')
model_f1 = f1_score(y_test, y_pred_model, average='macro')
model_acc = accuracy_score(y_test, y_pred_model)

st.subheader(f'Classifier = DNN')  
st.write(f'Accuracy =', model_acc)   
st.write(f'F1 Score =', model_f1)  
st.write(f'AUC - ROC Score =', model_auc)  

model_auc_att = roc_auc_score(y_test,y_prediction_attack_model, multi_class='ovr')
model_f1_att = f1_score(y_test, y_pred_attack_model, average='macro')
model_acc_att = accuracy_score(y_test, y_pred_attack_model)

st.info(f'MLP Attack Classification = {attacks_name}')  
st.write(f'Accuracy =', model_acc_att) 
st.write(f'F1 Score =', model_f1_att)  
st.write(f'AUC - ROC Score =', model_auc_att)   


model_auc_tar = roc_auc_score(y_test,y_prediction_target_model, multi_class='ovr')
model_f1_tar = f1_score(y_test, y_pred_target_model, average='macro')
model_acc_tar = accuracy_score(y_test, y_pred_target_model)


st.info(f'MLP Targeted Attack Classification = {targeted_attacks_name}')  
st.write(f'Accuracy =', model_acc_tar) 
st.write(f'F1 Score =', model_f1_tar)  
st.write(f'AUC - ROC Score =', model_auc_tar)  


(unique, counts) = np.unique(y_test, return_counts=True)
f1 = np.asarray((unique, counts)).T
st.write("Original y_test", f1)

(unique, counts) = np.unique(y_pred_model, return_counts=True)
f2 = np.asarray((unique, counts)).T
st.write("Predicted y_test", f2)

(unique, counts) = np.unique(y_pred_attack_model, return_counts=True)
f3 = np.asarray((unique, counts)).T
st.write("y_test After Untargeted Attack ", f3)

(unique, counts) = np.unique(y_pred_target_model, return_counts=True)
f4 = np.asarray((unique, counts)).T
st.write("y_test After Targeted Attack", f4)



# set width of bar
# barWidth = 0.25
# fig = plt.subplots(figsize =(12, 8))
 
ACC = [model_acc, model_acc_att, model_acc_tar]
FS = [model_f1, model_f1_att, model_f1_tar]
AUC = [model_auc, model_auc_att, model_auc_tar]
 
# # Set position of bar on X axis
# br1 = np.arange(len(ACC))
# br2 = [x + barWidth for x in br1]
# br3 = [x + barWidth for x in br2]
 
# # Make the plot
# plt.bar(br1, ACC, color ='c', width = barWidth,
#         edgecolor ='grey', label ='Accuracy')
# plt.bar(br2, FS, color ='m', width = barWidth,
#         edgecolor ='grey', label ='F1Score')
# plt.bar(br3, AUC, color ='g', width = barWidth,
#         edgecolor ='grey', label ='AUC-ROC')
 

# # Adding Xticks
# plt.title('Evaluation Metrics')
# plt.xlabel('Type', fontweight ='bold', fontsize = 15)
# plt.ylabel('Accuracy', fontweight ='bold', fontsize = 15)
# plt.xticks([r + barWidth for r in range(len(ACC))],
#         ['Original', 'Untargeted', 'Targeted'])
 
# plt.legend()
# plt.show()

# st.write(fig)
st.set_option('deprecation.showPyplotGlobalUse', False)

# st.pyplot()

EVAL = ['Original', 'Untargeted', 'Targeted']

plt.title('Accuracy With Each Attack')
plt.xlabel('Epsilon')
plt.ylabel('Accuracy')
plt.plot(EVAL , ACC, '-o', label='Accuracy')
plt.plot(EVAL, FS,'-o',  label='F1Score')
plt.plot(EVAL, AUC,'-o', label='AUC-ROC')


plt.legend()
plt.show()
st.pyplot()

    
    
clf = classifier.fit(X_train, y_train)
y_prediction= clf.predict_proba(X_test)
y_pred=np.argmax(y_prediction,axis=1)


y_prediction_attack = clf.predict_proba(X_adv)
y_pred_attack = np.argmax(y_prediction_attack ,axis=1)

y_prediction_target = clf.predict_proba(X_adv_tar)
y_pred_target = np.argmax(y_prediction_target ,axis=1)


class_auc = roc_auc_score(y_test,y_prediction, multi_class='ovr')
class_f1 = f1_score(y_test, y_pred, average='macro')
class_acc = accuracy_score(y_test, y_pred)

st.subheader(f'Classifier = {classifier_name}')
st.write(f'Accuracy =', class_acc)
st.write(f'F1 Score =', class_f1)  
st.write(f'AUC - ROC Score =', class_auc)  


class_auc_att = roc_auc_score(y_test,y_prediction_attack, multi_class='ovr')
class_f1_att = f1_score(y_test, y_pred_attack, average='macro')
class_acc_att= accuracy_score(y_test, y_pred_attack)

st.info(f'Attack Classification = {attacks_name}')
st.write(f'Accuracy =', class_acc_att)
st.write(f'F1 Score =', class_f1_att)  
st.write(f'AUC - ROC Score =', class_auc_att)  


class_auc_tar = roc_auc_score(y_test,y_prediction_target, multi_class='ovr')
class_f1_tar = f1_score(y_test, y_pred_target, average='macro')
class_acc_tar= accuracy_score(y_test, y_pred_target)

st.info(f'Targeted Attack Classification = {targeted_attacks_name}')
st.write(f'Accuracy =', class_acc_tar)
st.write(f'F1 Score =', class_f1_tar)  
st.write(f'AUC - ROC Score =', class_auc_tar)  



# (unique, counts) = np.unique(y_test, return_counts=True)
# f1 = np.asarray((unique, counts)).T
st.write("Original y_test", f1)

(unique, counts) = np.unique(y_pred, return_counts=True)
f5 = np.asarray((unique, counts)).T
st.write("Predicted y_test on Classifier", f5)

(unique, counts) = np.unique(y_pred_attack, return_counts=True)
f6 = np.asarray((unique, counts)).T
st.write("y_test After Untargeted Attack Classification", f6)

(unique, counts) = np.unique(y_pred_target, return_counts=True)
f7 = np.asarray((unique, counts)).T
st.write("y_test After Targeted Attack Classification", f7)




c_ACC = [class_acc, class_acc_att, class_acc_tar]
c_FS = [class_f1, class_f1_att, class_f1_tar]
c_AUC = [class_auc, class_auc_att, class_auc_tar]


# EVAL = ['Original', 'Untargeted', 'Targeted']

plt.ylabel('Accuracy')
plt.plot(EVAL , c_ACC, '-o', label='Accuracy')
plt.plot(EVAL, c_FS,'-o',  label='F1Score')
plt.plot(EVAL, c_AUC,'-o', label='AUC-ROC')


plt.legend()
plt.show()
st.pyplot()



st.snow()




############################################## Adversarial Training ################################



X_test_adv[:] = X_adv.numpy()

X_adv_tar_np = X_adv_tar.to_numpy()
X_test_adv_tar[:] = X_adv_tar_np


X_train_test = [X_train_df, X_test_adv]
X_adv_train = pd.concat(X_train_test)
X_adv_train.sort_index(inplace=True)

X_train_test_tar = [X_train_df, X_test_adv_tar]
X_adv_train_tar = pd.concat(X_train_test_tar)
X_adv_train_tar.sort_index(inplace=True)

y_train_test = [y_train_df, y_test_df]
y_adv_train = pd.concat(y_train_test)
y_adv_train.sort_index(inplace=True)


adv_model= create_tf_model(np_x.shape[1],len(np.unique(np_y)))

st.success("Untargeted Adversarial MLP Model Created")
    
y_train_test_one = [encoder_df, encoder_df_test]
y_adv_train_one = pd.concat(y_train_test_one)
y_adv_train_one.sort_index(inplace=True)

# st.write('Shapee',y_adv_train_one.shape)

# X_adv_train_np = X_adv_train.to_numpy()
# y_adv_train_one_np = y_adv_train_one.to_numpy()

# st.write('Type', y_adv_train_one.dtype)
# st.write('Shape', y_adv_train_one.shape)

# X_adv_train_np = X_adv_train.toarray()
y_adv_train_one_np = np.array(y_adv_train_one)


# st.write('Type', y_adv_train_one_np.dtype)
# st.write('Shape', y_adv_train_one_np.shape)

# y_adv_train_one_np = np.array(y_adv_train_one_np, dtype=np.object)

X_adv_train_np = np.array(X_adv_train)
# y_adv_train_one_np = np.asarray(y_adv_train_one_np).astype(np.int)


X_adv_tar_train_np = np.array(X_adv_train_tar)


history = adv_model.fit(X_adv_train_np, y_adv_train_one_np, epochs=5,
                        batch_size=50000, verbose=0,
                        validation_split=0.3)

st.success("Untargeted Adversarial MLP Model Trained")



adv_tar_model= create_tf_model(np_x.shape[1],len(np.unique(np_y)))

st.success("Targeted Adversarial MLP Model Created")
    
# one_hot_adv_ytrain_tar = np_utils.to_categorical(y_adv_train)

# st.write('Type', X_test_adv_tar.shape)
# st.write('Shape', y_adv_train_one_np.shape)

history = adv_tar_model.fit(X_adv_tar_train_np, y_adv_train_one_np, epochs=5,
                        batch_size=50000, verbose=0,
                        validation_split=0.3)

st.success("Targeted Adversarial MLP Model Trained")


########### testing dataset containing both xtrain and adv xtest with clean xtest ############## 
y_prediction_adv_model=adv_model.predict(X_test)
y_pred_adv_model=np.argmax(y_prediction_adv_model,axis=1)

########### testing dataset containing both xtrain and adv xtest with adv xtest ############## 
y_prediction_attack_adv_model = adv_model.predict(X_adv)
y_pred_attack_adv_model=np.argmax(y_prediction_attack_adv_model,axis=1)


y_prediction_attack_adv_model_tar = adv_model.predict(X_adv_tar)
y_pred_attack_adv_model_tar=np.argmax(y_prediction_attack_adv_model_tar,axis=1)

########### testing dataset containing both xtrain and adv targeted xtest with clean xtest ############## 
y_prediction_adv_tar_model=adv_tar_model.predict(X_test)
y_pred_adv_tar_model=np.argmax(y_prediction_adv_tar_model,axis=1)

########### testing dataset containing both xtrain and adv targeted xtest with targeted xtest ############## 

y_prediction_target_adv_model_untar = adv_tar_model.predict(X_adv)
y_pred_target_adv_model_untar=np.argmax(y_prediction_target_adv_model_untar,axis=1)


y_prediction_target_adv_model = adv_tar_model.predict(X_adv_tar)
y_pred_target_adv_model=np.argmax(y_prediction_target_adv_model,axis=1)




adv_model_auc = roc_auc_score(y_test,y_prediction_adv_model, multi_class='ovr')
adv_model_f1 = f1_score(y_test, y_pred_adv_model, average='macro')
adv_model_acc = accuracy_score(y_test, y_pred_adv_model)

st.subheader(f'Adversarial Training with Clean X_test = Untargeted Model ')  
st.write(f'Accuracy =', adv_model_acc)   
st.write(f'F1 Score =', adv_model_f1)  
st.write(f'AUC - ROC Score =', adv_model_auc)  


adv_model_auc_att = roc_auc_score(y_test,y_prediction_attack_adv_model, multi_class='ovr')
adv_model_f1_att = f1_score(y_test, y_pred_attack_adv_model, average='macro')
adv_model_acc_att = accuracy_score(y_test, y_pred_attack_adv_model)

st.info(f' Adversarial Training with Adversarial X_test = Untargeted Model')  
st.write(f'Accuracy =', adv_model_acc_att) 
st.write(f'F1 Score =', adv_model_f1_att)  
st.write(f'AUC - ROC Score =', adv_model_auc_att)   


adv_model_auc_att_tar = roc_auc_score(y_test,y_prediction_attack_adv_model_tar, multi_class='ovr')
adv_model_f1_att_tar = f1_score(y_test, y_pred_attack_adv_model_tar, average='macro')
adv_model_acc_att_tar = accuracy_score(y_test, y_pred_attack_adv_model_tar)

st.info(f' Adversarial Training with Targeted Adversarial X_test = Untargeted Model')  
st.write(f'Accuracy =', adv_model_acc_att_tar) 
st.write(f'F1 Score =', adv_model_f1_att_tar)  
st.write(f'AUC - ROC Score =', adv_model_auc_att_tar)  




at_ACC = [adv_model_acc, adv_model_acc_att, adv_model_acc_att_tar]
at_FS = [adv_model_f1, adv_model_f1_att, adv_model_f1_att_tar]
at_AUC = [adv_model_auc, adv_model_auc_att, adv_model_auc_att_tar]


EVAL1 = ['Clean X_test', 'Untargeted Adv X_test', 'Targeted Adv X_test']

plt.xlabel('Untargeted Model')
plt.ylabel('Accuracy')
plt.plot(EVAL1 , at_ACC, '-o', label='Accuracy')
plt.plot(EVAL1, at_FS,'-o',  label='F1Score')
plt.plot(EVAL1, at_AUC,'-o', label='AUC-ROC')

plt.legend()
plt.show()
st.pyplot()



adv_tar_model_auc = roc_auc_score(y_test,y_prediction_adv_tar_model, multi_class='ovr')
adv_tar_model_f1 = f1_score(y_test, y_pred_adv_tar_model, average='macro')
adv_tar_model_acc = accuracy_score(y_test, y_pred_adv_tar_model)

st.subheader(f'Adversarial Training with Clean X_test = Targeted Model')  
st.write(f'Accuracy =', adv_tar_model_acc) 
st.write(f'F1 Score =', adv_tar_model_f1)  
st.write(f'AUC - ROC Score =', adv_tar_model_auc)   


adv_tar_model_auc_att_untar = roc_auc_score(y_test,y_prediction_target_adv_model_untar, multi_class='ovr')
adv_tar_model_f1_att_untar = f1_score(y_test, y_pred_target_adv_model_untar , average='macro')
adv_tar_model_acc_att_untar = accuracy_score(y_test, y_pred_target_adv_model_untar)

st.info(f'Adversarial Training with Untargeted Adversarial X_test = Targeted Model')  
st.write(f'Accuracy =', adv_tar_model_acc_att_untar) 
st.write(f'F1 Score =', adv_tar_model_f1_att_untar)  
st.write(f'AUC - ROC Score =', adv_tar_model_auc_att_untar)   



adv_tar_model_auc_att = roc_auc_score(y_test,y_prediction_target_adv_model, multi_class='ovr')
adv_tar_model_f1_att = f1_score(y_test, y_pred_target_adv_model , average='macro')
adv_tar_model_acc_att = accuracy_score(y_test, y_pred_target_adv_model)

st.info(f'Adversarial Training with Targeted Adversarial X_test = Targeted Model')  
st.write(f'Accuracy =', adv_tar_model_acc_att) 
st.write(f'F1 Score =', adv_tar_model_f1_att)  
st.write(f'AUC - ROC Score =', adv_tar_model_auc_att)   


att_ACC = [adv_tar_model_acc, adv_tar_model_acc_att_untar, adv_tar_model_acc_att]
att_FS = [adv_tar_model_f1, adv_tar_model_f1_att_untar, adv_tar_model_f1_att]
att_AUC = [adv_tar_model_auc, adv_tar_model_auc_att_untar, adv_tar_model_auc_att]


EVAL1 = ['Clean X_test', 'Untargeted Adv X_test', 'Targeted Adv X_test']

plt.xlabel('Targeted Model')
plt.ylabel('Accuracy')
plt.plot(EVAL1 , att_ACC, '-o', label='Accuracy')
plt.plot(EVAL1, att_FS,'-o',  label='F1Score')
plt.plot(EVAL1, att_AUC,'-o', label='AUC-ROC')

plt.legend()
plt.show()
st.pyplot()



#################################### CHASSIFIERS ADVERSAREIAL TRAINING ##################################

y_adv_train_clf = np.argmax(y_adv_train_one_np ,axis=1)


clf_adv = classifier.fit(X_adv_train_np, y_adv_train_clf)

y_prediction_clf = clf_adv.predict_proba(X_test)
y_pred_clf =np.argmax(y_prediction_clf,axis=1)


y_prediction_attack_clf = clf_adv.predict_proba(X_adv)
y_pred_attack_clf = np.argmax(y_prediction_attack_clf ,axis=1)

y_prediction_target_clf = clf_adv.predict_proba(X_adv_tar)
y_pred_target_clf = np.argmax(y_prediction_target_clf ,axis=1)


class_auc_clf = roc_auc_score(y_test,y_prediction_clf, multi_class='ovr')
class_f1_clf = f1_score(y_test, y_pred_clf, average='macro')
class_acc_clf = accuracy_score(y_test, y_pred_clf)

st.subheader(f'Adversarial Training with Clean X_test= {classifier_name}')
st.write(f'Accuracy =', class_acc_clf)
st.write(f'F1 Score =', class_f1_clf)  
st.write(f'AUC - ROC Score =', class_auc_clf)  


class_auc_att_clf = roc_auc_score(y_test,y_prediction_attack_clf, multi_class='ovr')
class_f1_att_clf = f1_score(y_test, y_pred_attack_clf, average='macro')
class_acc_att_clf= accuracy_score(y_test, y_pred_attack_clf)

st.info(f'Adversarial Training with Untargeted Attack= {attacks_name}')
st.write(f'Accuracy =', class_acc_att_clf)
st.write(f'F1 Score =', class_f1_att_clf)  
st.write(f'AUC - ROC Score =', class_auc_att_clf)  


class_auc_tar_clf = roc_auc_score(y_test,y_prediction_target_clf, multi_class='ovr')
class_f1_tar_clf = f1_score(y_test, y_pred_target_clf, average='macro')
class_acc_tar_clf= accuracy_score(y_test, y_pred_target_clf)

st.info(f'Adversarial Training with Targeted Attack = {targeted_attacks_name}')
st.write(f'Accuracy =', class_acc_tar_clf)
st.write(f'F1 Score =', class_f1_tar_clf)  
st.write(f'AUC - ROC Score =', class_auc_tar_clf)  



cl_ACC = [class_acc_clf, class_acc_att_clf, class_acc_tar_clf]
cl_FS = [class_f1_clf, class_f1_att_clf, class_f1_tar_clf]
cl_AUC = [class_auc_clf, class_auc_att_clf, class_auc_tar_clf]


# EVAL1 = ['Clean X_test', 'Untargeted Adv X_test', 'Targeted Adv X_test']

plt.xlabel('Classifier')
plt.ylabel('Accuracy')
plt.plot(EVAL1 , cl_ACC, '-o', label='Accuracy')
plt.plot(EVAL1, cl_FS,'-o',  label='F1Score')
plt.plot(EVAL1, cl_AUC,'-o', label='AUC-ROC')

plt.legend()
plt.show()
st.pyplot()


st.balloons()

# y_adv_train




#### PLOT DATASET ####
# Project the data onto the 2 primary principal components
# pca = PCA(2)
# X_projected = pca.fit_transform(X)

# x1 = X_projected[:, 0]
# x2 = X_projected[:, 1]

# fig = plt.figure()
# plt.scatter(x1, x2,
#         c=y, alpha=0.8,
#         cmap='viridis')

# plt.xlabel('Principal Component 1')
# plt.ylabel('Principal Component 2')
# plt.colorbar()

# #plt.show()
# st.pyplot(fig)
# if attacks_classification=='KNN':
  
#     y_prediction_attack = classifier.predict(X_adv)
#     y_pred_attack = np.argmax(y_prediction_attack ,axis=1)


# elif attacks_classification=='Decision Tree':
   
#     y_prediction_attack = classifier.predict(X_adv)
#     y_pred_attack = np.argmax(y_prediction_attack ,axis=1)

# elif attacks_classification=='Naive Bayes':
  
   
#     y_prediction_attack = classifier.predict(X_adv)
#     y_pred_attack = np.argmax(y_prediction_attack ,axis=1)



# attack=attackclassi(classifier, X_adv,attacks_classification)
# y_pred_adv_classi=np.argmax(attack,axis=1)




