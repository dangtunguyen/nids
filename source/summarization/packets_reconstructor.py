import numpy as np
from scipy import spatial

def reconstruct_matrix(U, S, V, rank):
	U = np.append(U, np.zeros((len(U) , rank)), axis=1)
	S = np.append(S, np.zeros(rank))
	V = np.append(V, np.zeros((rank, V.shape[1])), axis = 0)
	return np.dot(U, np.dot(np.diag(S), V))
	
def get_membership_count(kmean_model, maxtrix_len):
	membership_count = np.bincount(kmean_model.labels_)
	
	## The remaining bins should have frequency of 1
	if len(membership_count) < maxtrix_len:
		membership_count += np.ones(maxtrix_len-len(membership_count))
	return membership_count
