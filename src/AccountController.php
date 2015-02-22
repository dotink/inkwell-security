<?php namespace Inkwell\Security
{
	use IW\HTTP;

	use Inkwell\Auth;
	use Inkwell\View;
	use Inkwell\Controller;

	use Dotink\Flourish\Message;

	use JWT;
	use SignatureInvalidException;

	use Exception;

	/**
	 * Handles various account activities
	 *
	 * @copyright Copyright (c) 2015, Matthew J. Sahagian
	 * @author Matthew J. Sahagian [mjs] <msahagian@dotink.org>
	 *
	 * @license Please reference the LICENSE.md file at the root of this distribution
	 *
	 * @package Dotink\Inkwell
	 */
	class AccountController extends Controller\BaseController implements Auth\ConsumerInterface
	{
		use Auth\ControllerConsumer;

		const MSG_LOGIN              = 'You must be logged in to access that resource.';
		const MSG_LOGIN_DIFFERENT    = 'You do not have permissions to access that resources, try logging in as a different user.';
		const MSG_INCORRECT_USER     = 'Your username appears to be incorrect';
		const MSG_INVALID_TOKEN      = 'Your token is invalid or expired, please try joining again';
		const MSG_INVALID_PASSWORD   = 'The password you supplied was incorrect, please try again';
		const MSG_MISSING_LOGIN_INFO = 'You must supply a login and password to login';

		/**
		 * The user's login (generally e-mail, but can be whatever)
		 *
		 * @access protected
		 * @var string
		 */
		protected $login = NULL;


		/**
		 * The user provider responsible for actually doing user work
		 *
		 * @access protected
		 * @var UserProviderInterface
		 */
		protected $userProvider = NULL;


		/**
		 * Create a new account controller
		 *
		 * @access public
		 * @param View $view The view objects for rendering templates to the screen
		 * @param Message $message A message object for creating/storing/retrieving flash messages
		 * @param UserProviderInterface $user_provider A user provider for resolving user details
		 * @return void
		 */
		public function __construct(View $view, Message $message, UserProviderInterface $user_provider = NULL)
		{
			$this->view         = $view;
			$this->message      = $message;
			$this->userProvider = $user_provider;
		}


		/**
		 * Prepare the controller
		 *
		 * If no user provider is provided and the action is anything other than the forbidden
		 * handler then we're going to 404.  There's nothing we can do without a user provider.
		 *
		 * @access public
		 * @param string $action The action being called
		 * @param array $context The router provided context
		 * @return void
		 */
		public function __prepare($action, $context = array())
		{
			parent::__prepare($action, $context);

			if (!$this->userProvider && $action != 'forbidden') {
				$this->response->setStatus(HTTP\NOT_FOUND);
				$this->router->defer(NULL);
			}

			$this->view->load('account/' . $action . '.html');
			$this->view->set('message', $this->message);
		}


		/**
		 * Handles resources which are forbidden to the current user
		 *
		 * This can be either because the user is not logged in or because they don't have
		 * the appropriate permissions.  If the user is not an anonymous user, then it's assumed
		 * they don't have permissions and the appropriate message is given.
		 *
		 * @access public
		 * @return View A forbidden view if no user provider is registered
		 */
		public function forbidden()
		{
			if ($this->userProvider) {
				$this->userProvider->setLoginRedirect(
					$this->auth->entity,
					$this->request->getURL()->getPathWithQuery()
				);

				if ($this->userProvider->verifyUser($this->auth->entity)) {
					$this->message->create('error', self::MSG_LOGIN);
				} else {
					$this->message->create('error', self::MSG_LOGIN_DIFFERENT);
				}

				return $this->router->redirect(
					$this->userProvider->getLogoutRedirect(),
					HTTP\REDIRECT_SEE_OTHER,
					FALSE
				);
			}

			return $this->view;
		}


		/**
		 * Allow a user to join
		 *
		 * @access public
		 * @return View The view for getting user information
		 */
		public function join()
		{
			if ($this->request->checkMethod(HTTP\POST)) {
				$params = $this->request->params;
				$token  = JWT::encode($params->get(), session_id());

				try {
					$this->userProvider->handleJoin(
						$params,
						$token,
						$this->view
					);

				} catch (Exception $e) {
					$this->message->create('error', $e->getMessage());
				}
			}

			return $this->view;
		}


		/**
		 * Logs a user into the system using the user provider
		 *
		 * @access public
		 * @return mixed|View The user object or a view object depending on how accessed
		 */
		public function login()
		{
			//
			// Try to get the user from a cookie
			//

			$user = $this->getUserFromCookie();

			//
			// If we're not the entry action, we're being used to get the logged in user
			//

			if (!$this->router->isEntryAction([$this, __FUNCTION__])) {
				return $user ?: $this->userProvider->getUser(NULL);
			}

			//
			// If we already have a user, then they're logged in, don't show them the login page
			//

			if ($user) {
				$this->completeLogin($user);
			}

			//
			// Actually try to log a user in
			//

			if ($this->request->checkMethod(HTTP\POST)) {
				$login    = $this->request->params->get('login');
				$password = $this->request->params->get('password');

				if ($login && $password) {
					$user = $this->userProvider->getUser($login);

					if (!$user) {
						$this->message->create('error', self::MSG_INCORRECT_USER);

					} elseif (!$this->userProvider->verifyPassword($user, $password)) {
						$this->message->create('error', self::MSG_INVALID_PASSWORD);

					} else {
						$this->completeLogin($user);
					}

				} else {
					$this->message->create('error', self::MSG_MISSING_LOGIN_INFO);
				}
			}

			return $this->view;
		}


		/**
		 * Logs a user out
		 *
		 * @access public
		 * @return Response A response to redirect the user after logout
		 */
		public function logout()
		{
			$user = $this->getUserFromCookie();

			$this->revokeUserCookie();

			$this->response->setStatusCode(HTTP\REDIRECT_SEE_OTHER);
			$this->response->headers->set('Location', $this->request->getURL()->modify(
				$this->userProvider->getLogoutRedirect($user)
			));


			return $this->response;
		}


		/**
		 * Allow a user to register
		 *
		 * @access public
		 * @return View The registration view to request user registration information
		 */
		public function register()
		{
			$params = $this->request->params;
			$token  = $params->get('token', NULL);

			if (!$token) {
				$this->router->redirect($this->userProvider->getJoinPath());

			}  else {

				try {
					$token_data = (array) JWT::decode($token, session_id());

				} catch (SignatureInvalidException $e) {
					$this->message->create('error', self::MSG_INVALID_TOKEN);
					$this->router->redirect($this->userProvider->getJoinPath());
				}

				if ($this->request->checkMethod(HTTP\POST)) {
					try {
						$user = $this->userProvider->handleRegister(
							$params,
							$token_data,
							$this->view
						);

						$this->completeLogin($user);

					} catch (Exception $e) {
						$this->message->create('error', $e->getMessage());
					}
				}
			}

			return $this->view;
		}


		/**
		 * Rrefresh a user's authentication cookie
		 *
		 * @access public
		 * @return void
		 */
		public function refresh()
		{
			if (!$this->login || $this->response->cookies->has('security_user')) {
				return;
			}

			session_regenerate_id(TRUE);

			$this->response->cookies->set('security_user', [
				'login' => $this->login,
				'token' => session_id(),
				'limit' => strtotime('+30 minutes')
			]);
		}


		/**
		 * Complete a user login by setting their login, refreshing cookie, and redirecting
		 *
		 * @access public
		 * @return void
		 */
		private function completeLogin($user)
		{
			$this->login = $this->userProvider->getLogin($user);

			$this->refresh();

			$this->response->setStatusCode(HTTP\REDIRECT_SEE_OTHER);
			$this->response->headers->set('Location', $this->request->getURL()->modify(
				$this->userProvider->getLoginRedirect($user)
			));

			$this->router->demit(NULL);
		}


		/**
		 * Gets a user from their authentication cookie
		 *
		 * @access public
		 * @return mixed The user based on the cookie
		 */
		private function getUserFromCookie()
		{
			$user = $this->request->cookies->get('security_user');

			if (!$user || $user->limit < time() || session_id() != $user->token) {
				return NULL;

			} else {
				$this->login = $user->login;
			}

			return $this->userProvider->getUser($this->login);
		}


		/**
		 * Revoke a user cookie by expiring it
		 *
		 * @access public
		 * @return void
		 */
		private function revokeUserCookie()
		{
			$this->response->cookies->set('security_user', NULL);
		}
	}
}
