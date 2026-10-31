import joblib

features = joblib.load(r'F:\all_10_csv_manual\feature_columns.pkl')
print(f'Feature count: {len(features)}')
print('\nFeatures:')
for i, f in enumerate(features):
    print(f'{i+1}. {f}')
