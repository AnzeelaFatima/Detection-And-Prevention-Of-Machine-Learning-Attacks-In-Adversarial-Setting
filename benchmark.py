# from sklearn.datasets import fetch_kddcup99
# import numpy as np
# import pandas as pd



# import sklearn 

# from sklearn.preprocessing import LabelEncoder, OneHotEncoder
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import StandardScaler 
# from sklearn.model_selection import train_test_split





# def kdd_benchmark():
   
       
#     np.random.seed(10)
       
#     All_Column = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes',
#                     'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
#                     'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
#                     'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
#                     'num_access_files', 'num_outbound_cmds', 'is_host_login',
#                     'is_guest_login', 'count', 'srv_count', 'serror_rate',
#                     'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
#                     'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
#                     'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
#                     'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
#                     'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
#                     'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
       
#     Cat_COL = ['protocol_type', 'service', 'flag', 'land',  'logged_in', 'is_host_login', 'is_guest_login' ]
       
       
#     Num_Column = [ 'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment',
#                         'urgent', 'hot', 'num_failed_logins', 'num_compromised',
#                         'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
#                         'num_shells', 'num_access_files', 'num_outbound_cmds', 'count',
#                         'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
#                         'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
#                         'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
#                         'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
#                         'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
#                         'dst_host_serror_rate', 'dst_host_srv_serror_rate',
#                         'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
       
       
#         ############################ Data preprocessing ################################
       
#     np_x, np_y = fetch_kddcup99(return_X_y=True, shuffle=False)
#     df_kddcup = pd.DataFrame(np_x, columns=All_Column)
#     df_kddcup['label'] = np_y
#         # df_kddcup.drop_duplicates(keep='first', inplace=True)
#     df_kddcup['label'] = df_kddcup['label'].apply(lambda d: \
#                                             str(d).replace('.', '').replace("b'", "").\
#                                                 replace("'", ""))
       
#     conversion_dict = {'back':'dos', 'buffer_overflow':'u2r', 'ftp_write':'r2l',
#                                'guess_passwd':'r2l', 'imap':'r2l', 'ipsweep':'probe',
#                                'land':'dos', 'loadmodule':'u2r', 'multihop':'r2l',
#                                'neptune':'dos', 'nmap':'probe', 'perl':'u2r', 'phf':'r2l',
#                                'pod':'dos', 'portsweep':'probe', 'rootkit':'u2r',
#                                'satan':'probe', 'smurf':'dos', 'spy':'r2l', 'teardrop':'dos',
#                                'warezclient':'r2l', 'warezmaster':'r2l'}
       
#     df_kddcup['label'] = df_kddcup['label'].replace(conversion_dict)
#     df_kddcup = df_kddcup.query("label != 'u2r'")
    
        
#     df_y = pd.DataFrame(df_kddcup.label, columns=["label"], dtype="category")
#     df_kddcup.drop(["label"], inplace=True, axis=1)
    
        
    
#     x_kddcup = df_kddcup[Num_Column].values
#     x= x_kddcup.mean()
#       #  x_kddcup= x_kddcup.fillna(x)
#     scaler = StandardScaler()
#     scaler.fit(x_kddcup)
#       #scaler.mean_
#       #scaler.scale_
#     x_kddcup=scaler.transform(x_kddcup)
#     print("TRansform",x_kddcup)
#       # mmc=MinMaxScaler()
#       # mmc.fit(x_kddcup)
#       # print("MMC",mmc.transform(x_kddcup))
      
#       #x_kddcup = preprocessing.scale(x_kddcup)
#     y_kddcup = df_y.label.cat.codes.to_numpy()
#     print("X     ",x_kddcup)
#     print("Y     ",y_kddcup)
    
    
    
#     df_x = pd.DataFrame(x_kddcup, columns = Num_Column)
    
#     df_y = pd.DataFrame(y_kddcup, columns =['label'])
#     result = pd.concat([df_x,df_y], axis=1)
#     return result
    
    
#     # df_y=result.iloc[:,-1]
#     # df_x=result.iloc[:,:-1]
    
#     # labelencoder = LabelEncoder()
#     # df_y = labelencoder.fit_transform(df_y)


# def kitsune():
    


   
#     data = pd.read_csv('D:/SYN_DoS_dataset.csv/SYN_DoS_dataset.csv')
#     datalabel = pd.read_csv('D:/SYN_DoS_labels.csv/SYN_DoS_labels.csv')
    
    
#     datalabel.drop(["Unnamed: 0"], inplace=True, axis=1)
    
#     data=data.sample(frac = 0.2) 
#     datalabel=datalabel.sample(frac = 0.2)
    
    

#           #  x_kddcup= x_kddcup.fillna(x)
#     scaler = StandardScaler()
#     scaler.fit(data)
#           #scaler.mean_
#           #scaler.scale_
#     x_kddcup=scaler.transform(data)
       

#     le = LabelEncoder()
#     datalabel=le.fit_transform(datalabel)  
    
        
        
#     df_x = pd.DataFrame(x_kddcup)
    
#     df_y = pd.DataFrame(datalabel, columns =['label'])
#     result = pd.concat([df_x,df_y], axis=1)
#     return result





from sklearn.datasets import fetch_kddcup99
import numpy as np
import pandas as pd
import sklearn 

from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler 
from sklearn.model_selection import train_test_split

import numpy as np
import pandas as pd
from cleverhans.tf2.attacks.fast_gradient_method import fast_gradient_method
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
import tensorflow.keras as tf1
from keras import backend as K 
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from keras.utils import np_utils
from sklearn.datasets import fetch_kddcup99
from sklearn.metrics import f1_score
from sklearn.metrics import roc_auc_score
from sklearn.metrics import classification_report
from sklearn.metrics import accuracy_score
import numpy as np
import pandas as pd
import tensorflow as tf




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
    


    data = pd.read_csv('E:/FYP2/ARP MitM/ARP_MitM_dataset.csv')
    datalabel = pd.read_csv('E:/FYP2/ARP MitM/ARP_MitM_labels.csv')
    
    
    
    # bool_series = pd.isnull(data)
    # print(bool_series)
    
    # if bool_series.all()==True:
    #     print(bool_series.all())
        
        
    # x = Dataset.iloc[:, :-1].values 
    # # importing an array of dependent variable
    # y = Dataset.iloc[:, -1].values
    # x=data.isnull().count()
    # print(x)
    
    # y=data.isnull().sum(axis = 1)
    # print(y)
    
    
    ## df1 as an example data frame 
    ## col1 name of column for which you want to calculate the nan values
    # sum(pd.isnull(data))
    
    
    
    
    
    def missing_values_table(data):
        mis_val = data.isnull().sum()
        mis_val_percent = 100 * data.isnull().sum() / len(data)
        mis_val_table = pd.concat([mis_val, mis_val_percent], axis=1)
        mis_val_table_ren_columns = mis_val_table.rename(
        columns = {0 : 'Missing Values', 1 : '% of Total Values'})
        mis_val_table_ren_columns = mis_val_table_ren_columns[
            mis_val_table_ren_columns.iloc[:,1] != 0].sort_values(
        '% of Total Values', ascending=False).round(1)
        print ("Your selected dataframe has " + str(data.shape[1]) + " columns.\n"      
            "There are " + str(mis_val_table_ren_columns.shape[0]) +
                " columns that have missing values.")
        return mis_val_table_ren_columns
    
    
    
    datalabel.drop(["Unnamed: 0"], inplace=True, axis=1)
    data=data.sample(frac = 0.5) 
    datalabel=datalabel.sample(frac = 0.5)
    
    
    datalabel = datalabel.replace([0,1],[1,0])
    
    result = pd.concat([data, datalabel], axis=1, join='inner')
    print(result)
    
    
    
    
    x1=missing_values_table(result)
    print(x1)
    # count_nan = len(data) - data.count()
    # print(count_nan)
    # data.info()
    # def drop_numerical_outliers(df, z_thresh=3):
    #     # Constrains will contain `True` or `False` depending on if it is a value below the threshold.
    #     constrains = df.select_dtypes(include=[np.number]) \
    #         .apply(lambda x: np.abs(stats.zscore(x)) < z_thresh, result_type='reduce') \
    #         .all(axis=1)
    #     # Drop (inplace) values set to be rejected
    #     df.drop(df.index[~constrains], inplace=True)
        
        
    # drop_numerical_outliers(result)
    print(data)
    numpy_array = result.to_numpy()
    print(type(numpy_array))
    
    # numpy_arr = datalabel.to_numpy()
    # print(type(numpy_arr))
    x= numpy_array.mean()
    np_x=np.nan_to_num(numpy_array,nan=x)
    print(np_x)
    y=pd.DataFrame(result.iloc[:,-1])
    x=pd.DataFrame(result.iloc[:,:-1])
    # labelencoder = LabelEncoder()
    # np_y = labelencoder.fit_transform(y)
    # print(np_y)
    sc_x = StandardScaler()
    sc_y = StandardScaler()
    sc_x.fit(x)
    np_d = sc_x.transform(x)
    print(np_d)
    print("                               ")
    
    df1=y.to_numpy()
    z=np.ndarray.flatten(df1)
    
    
    df_x = pd.DataFrame(np_d)
    
    df_y = pd.DataFrame(df1, columns =['label'])
    res = pd.concat([df_x,df_y], axis=1)
    return res


        


 








