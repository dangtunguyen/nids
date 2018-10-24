import numpy as np
from scipy.linalg import svd
from sklearn.cluster import KMeans

class PacketsSummary:
	## Perform SVD
	@staticmethod
	def truncated_svd(rank, normalized_matrix):
		try:
			U , S, V = np.linalg.svd(normalized_matrix, full_matrices=False)
			return U[:, :rank], S[:rank], V[:rank, :]
		except np.linalg.LinAlgError:
			print("[PacketsSummary.truncated_svd] Something went wrong!!!")
	
	## Perform 2 tasks: SVD and Kmeans
	@staticmethod
	def summarize(num_clusters, normalized_matrix, rank):
		U,S,V = PacketsSummary.truncated_svd(rank, normalized_matrix)
		model = KMeans(n_clusters=num_clusters, max_iter=600)
		return model.fit(U),S,V
