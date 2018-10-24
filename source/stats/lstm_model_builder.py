#!/usr/bin/env python

from keras.models import Sequential
from keras.layers import Dense, Activation, Dropout, TimeDistributed, Flatten
from keras.layers import LSTM

'''
Reference: https://keras.io/getting-started/sequential-model-guide/
A stateful recurrent model is one for which the internal states (memories) 
obtained after processing a batch of samples are reused as initial states 
for the samples of the next batch. This allows to process longer sequences 
while keeping computational complexity manageable.
'''
class LstmModelBuilder:
    def __init__(self, batch_size, timesteps, data_dim, stateful, epochs, hidden_size, model_save_path):
        self.batch_size = batch_size 
        self.timesteps = timesteps ## These are the past observations for a feature, such as lag variables
        self.data_dim = data_dim ## These are columns in your data
        self.stateful = stateful
        self.epochs = epochs
        self.hidden_size = hidden_size
        self.model_save_path = model_save_path # Path where trained model will be saved
        self.model = Sequential()
        self.create_model()
        
    def create_model(self):
        ## batch_input_shape: (batch_size, timesteps, data_dim)
        self.model.add(LSTM(self.hidden_size, return_sequences=True, batch_input_shape=(self.batch_size, self.timesteps, self.data_dim), stateful=self.stateful))
        self.model.add(LSTM(self.hidden_size, return_sequences=True, stateful=self.stateful))
        self.model.add(LSTM(self.hidden_size, return_sequences=True, stateful=self.stateful))
        self.model.add(Dropout(0.5))
        #self.model.add(Flatten())
        #self.model.add(Dense(1, activation='sigmoid'))
        self.model.add(TimeDistributed(Dense(1))) # output_dim=1
        self.model.add(Activation('sigmoid'))
        self.model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        print(self.model.summary())
    
    ## trainX: input data
    ## trainY: output label
    def train(self, trainX, trainY):
        history = self.model.fit(trainX, trainY, epochs=self.epochs, batch_size=self.batch_size, verbose=0, shuffle=False)
        print(history.history)
        
    def save(self):
        self.model.save(self.model_save_path)
