<?php
/*
* This file is based on Monarobase-Yubikey (Laravel 4).
* And was modified for Laravel 6 compatibility.
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

use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;
use Rapide\Yubikey\Contracts\YubikeyService;

class YubikeyServiceProvider extends ServiceProvider implements DeferrableProvider
{
    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/config/yubikey.php' => config_path('yubikey.php'),
        ]);
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('yubikey', function ($app) {
            return new Yubikey([
                'id' => config('yubikey.CLIENT_ID'),
                'key' => config('yubikey.SECRET_KEY'),
                'https' => config('yubikey.HTTPS'),
                'httpsverify' => config('yubikey.VERIFY_HTTPS'),
                'url_list' => config('yubikey.URL_LIST'),
                'user_agent' => config('yubikey.USER_AGENT'),
            ]);
        });
        $this->app->singleton(YubikeyService::class, 'yubikey');
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return [
            'yubikey',
            YubikeyService::class
        ];
    }

}