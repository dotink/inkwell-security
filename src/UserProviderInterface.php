<?php namespace Inkwell\Security
{
	use Inkwell\View;
	use Dotink\Flourish\Collection;

	/**
	 * Provides user creation and management abstraction for auth services
	 *
	 * @copyright Copyright (c) 2015, Matthew J. Sahagian
	 * @author Matthew J. Sahagian [mjs] <msahagian@dotink.org>
	 *
	 * @license Please reference the LICENSE.md file at the root of this distribution
	 *
	 * @package Dotink\Inkwell
	 */
	interface UserProviderInterface
	{
		/**
		 * Get the path to join
		 *
		 * @access public
		 * @return string The join path
		 */
		public function getJoinPath();


		/**
		 * Get the path to login
		 *
		 * @access public
		 * @return string The login path
		 */
		public function getLoginPath();


		/**
		 * Get the path to redirect a user to based on the user
		 *
		 * @access public
		 * @param mixed $user The user
		 * @return string The path to redirect to
		 */
		public function getLoginRedirect($user);


		/**
		 * Get the path to redirect a user to when they log out, based on the user
		 *
		 * @access public
		 * @param mixed $user The user
		 * @return string The path to redirect to on logout
		 */
		public function getLogoutRedirect($user);


		/**
		 * Retrieve a user with a given login
		 *
		 * @access public
		 * @param string $login The login for which we're retrieving the user, login may be NULL
		 * @return mixed The user or NULL if the user cannot be found
		 */
		public function getUser($login);


		/**
		 * Gets a login from a user
		 *
		 * @access public
		 * @param mixed $user The user with which we should get the login
		 * @return string The login for the user, NULL if user is invalid
		 */
		public function getUserLogin($user);


		/**
		 * Handle joining
		 *
		 * @access public
		 * @param Collection $params The request parameter collection
		 * @param string $token The JWT token for the join request
		 * @param View $view The view object which will be displayed on the join request
		 * @return void
		 */
		public function handleJoin(Collection $params, $token, View $view);


		/**
		 * Handle registration
		 *
		 * @access public
		 * @param Collection $params The request parameter collection
		 * @param array $token_data The data provided by the JWT token for the join request
		 * @param View $view The view object which will be displayed on the register request
		 * @return mixed The user to log in post-registration
		 */
		public function handleRegister(Collection $params, array $token_data, View $view);


		/**
		 * Set a login redirect for a user
		 *
		 * @access public
		 * @param mixed $user The user
		 * @param string $location The location to redirect to on successful login request
		 * @return void
		 */
		public function setLoginRedirect($user, $location);


		/**
		 * Set the passwword for a user
		 *
		 * @access public
		 * @param mixed $user The user
		 * @param string $password The password to set
		 * @return void
		 */
		public function setPassword($user, $password);


		/**
		 * Verify the password for a user
		 *
		 * @access public
		 * @param mixed $user The user
		 * @param string $password The password to verify
		 * @return boolean TRUE if the password matches the user's, FALSE otherwise
		 */
		public function verifyPassword($user, $password);


		/**
		 *
		 *
		 * @access public
		 * @param mixed $user The user
		 * @return boolean TRUE if the user exists and/or is valid, FALSE otherwise
		 */
		public function verifyUser($user);
	}
}
