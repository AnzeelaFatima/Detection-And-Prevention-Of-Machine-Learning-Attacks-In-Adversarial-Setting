from sklearn.datasets import fetch_kddcup99
import numpy as np
import pandas as pd



import sklearn 

from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler 
from sklearn.model_selection import train_test_split





def kdd_benchmark():
   
       
    np.random.seed(10)
       
    All_Column = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
                    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                    'num_access_files', 'num_outbound_cmds', 'is_host_login',
                    'is_guest_login', 'count', 'srv_count', 'serror_rate',
                    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
                    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
                    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
       
    Cat_COL = ['protocol_type', 'service', 'flag', 'land',  'logged_in', 'is_host_login', 'is_guest_login' ]
       
       
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
       
       
        ############################ Data preprocessing ################################
       
    np_x, np_y = fetch_kddcup99(return_X_y=True, shuffle=False)
    df_kddcup = pd.DataFrame(np_x, columns=All_Column)
    df_kddcup['label'] = np_y
        # df_kddcup.drop_duplicates(keep='first', inplace=True)
    df_kddcup['label'] = df_kddcup['label'].apply(lambda d: \
                                            str(d).replace('.', '').replace("b'", "").\
                                                replace("'", ""))
       
    conversion_dict = {'back':'dos', 'buffer_overflow':'u2r', 'ftp_write':'r2l',
                               'guess_passwd':'r2l', 'imap':'r2l', 'ipsweep':'probe',
                               'land':'dos', 'loadmodule':'u2r', 'multihop':'r2l',
                               'neptune':'dos', 'nmap':'probe', 'perl':'u2r', 'phf':'r2l',
                               'pod':'dos', 'portsweep':'probe', 'rootkit':'u2r',
                               'satan':'probe', 'smurf':'dos', 'spy':'r2l', 'teardrop':'dos',
                               'warezclient':'r2l', 'warezmaster':'r2l'}
       
    df_kddcup['label'] = df_kddcup['label'].replace(conversion_dict)
    df_kddcup = df_kddcup.query("label != 'u2r'")
    
        
    df_y = pd.DataFrame(df_kddcup.label, columns=["label"], dtype="category")
    df_kddcup.drop(["label"], inplace=True, axis=1)
    
        
    
    x_kddcup = df_kddcup[Num_Column].values
    x= x_kddcup.mean()
      #  x_kddcup= x_kddcup.fillna(x)
    scaler = StandardScaler()
    scaler.fit(x_kddcup)
      #scaler.mean_
      #scaler.scale_
    x_kddcup=scaler.transform(x_kddcup)
    print("TRansform",x_kddcup)
      # mmc=MinMaxScaler()
      # mmc.fit(x_kddcup)
      # print("MMC",mmc.transform(x_kddcup))
      
      #x_kddcup = preprocessing.scale(x_kddcup)
    y_kddcup = df_y.label.cat.codes.to_numpy()
    print("X     ",x_kddcup)
    print("Y     ",y_kddcup)
    
    
    
    df_x = pd.DataFrame(x_kddcup, columns = Num_Column)
    
    df_y = pd.DataFrame(y_kddcup, columns =['label'])
    result = pd.concat([df_x,df_y], axis=1)
    return result
    
    
    # df_y=result.iloc[:,-1]
    # df_x=result.iloc[:,:-1]
    
    # labelencoder = LabelEncoder()
    # df_y = labelencoder.fit_transform(df_y)


def kitsune():
    


   
    data = pd.read_csv('D:/SYN_DoS_dataset.csv/SYN_DoS_dataset.csv')
    datalabel = pd.read_csv('D:/SYN_DoS_labels.csv/SYN_DoS_labels.csv')
    
    
    datalabel.drop(["Unnamed: 0"], inplace=True, axis=1)
    
    data=data.sample(frac = 0.2) 
    datalabel=datalabel.sample(frac = 0.2)
    
    
    
    
    
    
        # print(data)
        # numpy_array = data.to_numpy()
        # print(type(numpy_array))
    
        # numpy_arr = datalabel.to_numpy()
        # print(type(numpy_arr))
    
        # x= numpy_array.mean()
        # np_x=np.nan_to_num(numpy_array,nan=x)
        # print(np_x)
        
        
        
        
        
          #  x_kddcup= x_kddcup.fillna(x)
    scaler = StandardScaler()
    scaler.fit(data)
          #scaler.mean_
          #scaler.scale_
    x_kddcup=scaler.transform(data)
       
          # mmc=MinMaxScaler()
          # mmc.fit(x_kddcup)
          # print("MMC",mmc.transform(x_kddcup))
          
          #x_kddcup = preprocessing.scale(x_kddcup)
    # y_kddcup = datalabel.cat.codes.to_numpy()
    
    le = LabelEncoder()
    datalabel=le.fit_transform(datalabel)  
    
        
        
    df_x = pd.DataFrame(x_kddcup)
    
    df_y = pd.DataFrame(datalabel, columns =['label'])
    result = pd.concat([df_x,df_y], axis=1)
    return result




 








