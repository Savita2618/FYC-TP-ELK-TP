import pandas as pd
df = pd.read_csv('/home/adminml/ssh_dataset.csv')
print(df.head())
print(df.describe())
print(df['label'].value_counts())
print(f"Taux d'attaque : {df['label'].mean()*100:.1f}%")