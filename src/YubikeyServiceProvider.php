<?php
 /*
 * This file is based on Monarobase-Yubikey (Laravel 4).
 * And was modified for Laravel 5 compatibility.
 *
 * (c) 2015 Christian Hermann
 * (c) 2013 Monarobase
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 *
 * @author    Monarobase
 * @author    Christian Hermann
 * @package     Yubikey
 * @copyright   (c) 2013 Monarobase <jonathan@monarobase.net> 
 *              (c) 2015 Chistian Hermann <c.hermann@bitbeans.de>
 * @link        http://monarobase.net
 * @link        https://github.com/bitbeans
 */

namespace Rapide\Yubikey;

use Illuminate\Support\ServiceProvider;

class YubikeyServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = true;

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot() 
	{
	    $this->publishes([
	        __DIR__.'/config/yubikey.php' => config_path('yubikey.php'),
	    ]);
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
        $this->app->singleton('yubikey', function($app) {
            return new Yubikey([
                'id' => config('yubikey.CLIENT_ID'),
                'key' => config('yubikey.SECRET_KEY'),
                'https' => config('yubikey.HTTPS'),
                'httpsverify' => config('yubikey.VERIFY_HTTPS'),
                'url_list' => config('yubikey.URL_LIST'),
                'user_agent' => config('yubikey.USER_AGENT'),
            ]);
        });
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return [
		    'yubikey'
        ];
	}

}