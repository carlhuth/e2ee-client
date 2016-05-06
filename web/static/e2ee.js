var e2ee

    (function() {
    'use strict';

    e2ee = {}
    e2ee.settings = {}

    e2ee.session = {
        isReady: false,
        cryptonSession: null,
        indexContainer: null,
        keys: {},
        keyPairReady: false,
        currentFile: {
            fileObject: null,
            fileName: '',
            encryptedChunks: [],
            decryptedChunks: []
        }
    }

    e2ee.util = {}

    e2ee.util.resetCurrentFile = function() {
        delete e2ee.session.currentFile
        e2ee.session.currentFile = {
            fileObject: null,
            fileName: '',
            encryptedChunks: [],
            decryptedChunks: [],
            streamEncryptor: null,
            streamDecryptor: null
        }
    }

    e2ee.crypto = {}

    // Chunk size (in bytes)
    // Warning: Must not be less than 256 bytes
    e2ee.crypto.chunkSize = 1024 * 1024 * 1

    e2ee.crypto.addChunkToContainer = function(chunk_id, chunk, fileContainer) {
        fileContainer.get('chunks', function(err, chunks) {
            if (err) {
                if (window.console && window.console.log) {
                    console.error(err)
                    console.error('value for chunks key of the file (that is being encrypted) container cannot be retrieved')
                }
            } else {
                chunks[chunk_id] = chunk
            }
        })
    }

    e2ee.crypto.deleteFile = function(fileName, callback) {
        e2ee.session.cryptonSession.deleteContainer(fileName, function(err, container) {
            if (err) {
                if (window.console && window.console.log) {
                    console.error(err)
                }
            } else {
                callback()
                if (window.console && window.console.log) {
                    e2ee.UI.showInfo(fileName, 'Deletion was successful.', true)
                }
            }
        })
    }
    
    e2ee.crypto.getContainerByHmac = function(fileHmacName, peerName, fileName, callback1) {
    	e2ee.session.cryptonSession.getPeer(peerName, function callback(err, peer) {
            if (err) {
                if (window.console && window.console.log) {
                    console.error(err)
                }
                return
            }
            e2ee.session.cryptonSession.loadWithHmac(fileHmacName, peer, function(err, fileContainer) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                    }
                } else {
                	fileContainer.name = fileName // when loading with hmac, file name is not set
                	callback1(fileContainer)
                }
            })
        })
    }

    e2ee.crypto.downloadFileByHmac = function(hmac, peerName, fileName) {
        e2ee.crypto.getContainerByHmac(hmac, peerName, fileName, function(fileContainer) {
			fileContainer.get('chunks', function(err, chunks) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                        console.info('file not available: ' + hmac)
                    }
                } else {
                    var decryptedChunks = []
                    Object.keys(chunks).forEach(function(key) { // keys are data positions
                        var a = chunks[key]
                        // convert object to array of values:
                        var arr = Object.keys(a).map(function(key) {
                            return a[key]
                        })
                        //var v = String.fromCharCode.apply(null, arr) // if you want to see the plaintext
                        decryptedChunks.push(new Uint8Array(arr))
                    });
                    var blob = new Blob(decryptedChunks)
                    saveAs(blob, fileName)
                }
            })
        })
    }
    
    e2ee.crypto.getContainer = function(name, callback){
   		e2ee.session.cryptonSession.load(name, function(err, fileContainer) {
        	if (err) {
        	    if (window.console && window.console.log) {
        	        console.info(err)
                }
        	} else {
        		callback(fileContainer)
			}
		})	
    }

    e2ee.crypto.downloadFile = function(fileName) {
        e2ee.UI.animateProgressBar(0, 1)
        e2ee.session.indexContainer.get('fileNames', function(err, fileNames) {
            if (err) {
                if (window.console && window.console.log) {
                    console.info(err)
                    console.info('file names from indexContainer could not be retrieved')
                }
                return
            }
            var filesList = fileNames['notMineFiles']
            for (var i = 0; i < filesList.length; i++) {
                var file = filesList[i]
                if (file.fileName === fileName) {
                    e2ee.crypto.downloadFileByHmac(file.hmac, file.peer, file.fileName)
                    return
                }
            }
           	e2ee.crypto.getContainer(fileName, function(fileContainer) { 
            	fileContainer.get('chunks', function(err, chunks) {
                	if (err) {
                    	if (window.console && window.console.log) {
                        	console.info(err)
                        	console.info('file not available: ' + fileName)
                    	}
                	} else {
                    	var decryptedChunks = []
                    	Object.keys(chunks).forEach(function(key) { // keys are data positions
                        	var a = chunks[key]
                            // convert object to array of values:
                        	var arr = Object.keys(a).map(function(key) {
                                return a[key]
                            })
                            //var v = String.fromCharCode.apply(null, arr) // if you want to see the plaintext
                        	decryptedChunks.push(new Uint8Array(arr))
                    	});
                    	var blob = new Blob(decryptedChunks)
                    	saveAs(blob, fileName)
                    	e2ee.UI.animateProgressBar(1, 1)
                    	e2ee.UI.clearAfterDownloading(fileName)
                	}
            	})
            })
        })
    }

    e2ee.crypto.encryptFile = function(file, callback) {
        e2ee.session.currentFile.fileName = file.name

        e2ee.session.cryptonSession.load(file.name, function(err, fileContainer) {
            if (err) { // the file is not stored on Crypton yet
                e2ee.session.cryptonSession.create(file.name, function(err, fileContainer) {
                    if (err) {
                        if (window.console && window.console.log) {
                            console.error(err)
                            console.error('Crypton container for the file that is being encrypted could not be created')
                        }
                    } else {
                        fileContainer.add('chunks', function() {
                            var alreadyExists = false
                            e2ee.crypto.addNextChunkToContainer(file, fileContainer, 0, alreadyExists)
                        })
                    }
                })
            } else { // the file will be overwritten on Crypton
                var alreadyExists = true
                e2ee.crypto.addNextChunkToContainer(file, fileContainer, 0, alreadyExists)
            }
        })
    }

    e2ee.crypto.addNextChunkToContainer = function(file, fileContainer, dataPosition, alreadyExists) {
        e2ee.file.read(
            file,
            dataPosition,
            dataPosition + e2ee.crypto.chunkSize,
            function(chunk) {
                chunk = chunk.data
                var isLast = false
                if (dataPosition >= (file.size - e2ee.crypto.chunkSize)) {
                    isLast = true
                }
                var encryptedChunk

                e2ee.crypto.addChunkToContainer(dataPosition, chunk, fileContainer) // todo: this contains async call, but is used as sync
                e2ee.UI.animateProgressBar(dataPosition + e2ee.crypto.chunkSize, file.size)
                if (isLast) {
                    fileContainer.add('metadata', function() {
						fileContainer.get('metadata', function(err, meta) {
            				if (err) {
                				if (window.console && window.console.log) {
                    				console.error(err)
                    				console.error('value for metadata key of the file (that is being encrypted) container cannot be retrieved')
                				}
            				} else {
            					var metadata = "added " + new Date().toJSON().slice(0, 10)
                				meta["date"] = metadata
                            	fileContainer.save(function(err) {
                                	if (err) {
                                    	if (window.console && window.console.log) {
                                        	console.info(err)
                                    	}
                                    	e2ee.UI.showInfo(file.name, err, false)
                                    	e2ee.UI.fileOperationIsComplete(file.name)
                                	} else {
                                    	e2ee.UI.addFile(file.name, metadata, alreadyExists)
                                    	if (!alreadyExists) {
                                        	e2ee.session.indexContainer.get('fileNames', function(err, fileNames) {
                                            	fileNames['listOfFiles'].push(file.name)
                                            	e2ee.session.indexContainer.save(function(err) {
                                                	if (err) {
                                                    	if (window.console && window.console.log) {
                                                        	console.error(err)
                                                        	console.error('name of the file that is being encrypted could not be stored in indexContainer')
                                                    	}
                                                	}
                                            	})
                                        	})
                                    	}
                                    	e2ee.UI.showInfo(file.name, 'Encryption was successful.', true)
                                    	e2ee.UI.fileOperationIsComplete(file.name)
                                	}
                            	})
            				}
       					})
       				})
                } else {
                    dataPosition += e2ee.crypto.chunkSize
                    return e2ee.crypto.addNextChunkToContainer(
                        file,
                        fileContainer,
                        dataPosition,
                        alreadyExists
                    )
                }
            }
        )
    }

    e2ee.file = {}

    e2ee.file.read = function(file, start, end, callback, errorCallback) {
        var reader = new FileReader()
        reader.onload = function(readerEvent) {
            return callback({
                name: file.name,
                size: file.size,
                data: new Uint8Array(readerEvent.target.result)
            })
        }
        reader.onerror = function() {
            if (typeof(errorCallback) === 'function') {
                return errorCallback()
            } else {
                throw new Error('e2ee: File read error')
                return false
            }
        }
        reader.readAsArrayBuffer(file.slice(start, end))
    }

})()