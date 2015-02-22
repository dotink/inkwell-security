<?php namespace Inkwell\Security
{
	use UnexpectedValueException;
	use Inkwell\HTTP;
	use JWT;

	/**
	 * Encrypts cookie data in a JSON web token, by chance this allows for keyed data
	 *
	 * @copyright Copyright (c) 2015, Matthew J. Sahagian
	 * @author Matthew J. Sahagian [mjs] <msahagian@dotink.org>
	 *
	 * @license Please reference the LICENSE.md file at the root of this distribution
	 *
	 * @package Dotink\Inkwell
	 */
	class JWTCookieWrapper implements HTTP\CookieWrapperInterface
	{
		/**
		 * The key to use during encryption
		 *
		 * @access private
		 * @var string
		 */
		private $key = NULL;


		/**
		 * Create a new JWT Cookie Wrapper
		 *
		 * @access public
		 * @param string $key The key with which to encrypt JSON Web Tokens
		 * @return void
		 */
		public function __construct($key)
		{
			$this->key = $key;
		}


		/**
		 * Wrap data in a JSON Web Token
		 *
		 * @access public
		 * @param mixed $data The data to wrap
		 * @return string The encrypted JWT representing the data
		 */
		public function wrap($data)
		{
			return JWT::encode($data, $this->key);
		}


		/**
		 * Unwrap data in a JSON Web Token
		 *
		 * @access public
		 * @param string $data The data to unwrap
		 * @return mixed The encrypted JWT data, NULL if the key or token data is bad
		 */
		public function unwrap($data)
		{
			try {
				return JWT::decode($data, $this->key);
			} catch (UnexpectedValueException $e) {
				return NULL;
			}
		}
	}
}
