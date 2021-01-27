import Flutter
import UIKit
import FirebaseAuth

public class FirebaseAuthOAuthViewController: UIViewController, FlutterPlugin {
	
	private static let CREATE_USER_METHOD = "openSignInFlow"
	private static let LINK_USER_METHOD = "linkExistingUserWithCredentials"
	
	internal var currentNonce: String?
	private var call: FlutterMethodCall?
	private var result: FlutterResult?
	private(set) public var authProvider: OAuthProvider?
	var arguments: [String: String]?
	
	public static func register(with registrar: FlutterPluginRegistrar) {
		let channel = FlutterMethodChannel(name: "me.amryousef.apple.auth/firebase_auth_oauth", binaryMessenger: registrar.messenger())
		let instance = FirebaseAuthOAuthViewController()
		registrar.addMethodCallDelegate(instance, channel: channel)
	}
	
	public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
		self.result = result
		self.call = call
		if let arguments = call.arguments as? [String:String] {
			guard let providerId = arguments["provider"] else {
				finalizeResult(
					FirebaseAuthOAuthPluginError
						.PluginError(error: "Provider argument cannot be null")
				)
				return
			}
			if providerId == "apple.com" {
				if #available(iOS 13.0, *) {
					signInWithApple(arguments: arguments)
				} else {
					finalizeResult(FirebaseAuthOAuthPluginError.PluginError(error: "Sign in by Apple is not supported for this iOS version"))
				}
			} else {
				authProvider = OAuthProvider(providerID: providerId)
				oAuthSignIn(arguments: arguments)
			}
		} else {
			finalizeResult(FirebaseAuthOAuthPluginError.PluginError(error: "call arguments cannot be null"))
		}
	}
	
	func consumeCredentials(_ credential: AuthCredential) {
		if call?.method == FirebaseAuthOAuthViewController.CREATE_USER_METHOD {
			Auth.auth().signIn(with: credential) { authResult, error in
				if let firebaseError = error {
					self.finalizeResult(
						FirebaseAuthOAuthPluginError
							.FirebaseAuthError(error: firebaseError)
					)
					
				}else{
                    var token = ""
                    if let authCred = authResult?.credential as? OAuthCredential{
                        token = authCred.accessToken ?? ""
                    }
				self.finalizeResult(Auth.auth().currentUser!,token: token)
				}
			}
		}
		if call?.method == FirebaseAuthOAuthViewController.LINK_USER_METHOD {
			guard let currentUser = Auth.auth().currentUser else {
				self.finalizeResult(.PluginError(error: "currentUser is nil. Make sure a user exists when \(FirebaseAuthOAuthViewController.LINK_USER_METHOD) is used."))
				return
			}
			currentUser.link(with: credential) { (result, error) in
				if error != nil {
					self.finalizeResult(.FirebaseAuthError(error: error!))
				}
				if result != nil {
                    var token = ""
                    if let authCred = credential as? OAuthCredential{
                        token = authCred.accessToken ?? ""
                    }
					self.finalizeResult(currentUser,token: token)
				}
			}
		}
	}
	
	func finalizeResult(_ error: FirebaseAuthOAuthPluginError) {
        finalizeResult(user: nil, error: error,token:"")
	}
	
	func finalizeResult(_ user: User,token:String) {
		finalizeResult(user: user, error: nil,token: token)
	}
	
    private func finalizeResult(user: User?, error: FirebaseAuthOAuthPluginError?,token:String) {
		if user != nil {
			result?(token)
		}
		
		if error != nil {
			result?(error?.flutterError())
		}
		
		self.call = nil
		self.result = nil
		self.authProvider = nil
	}
}
