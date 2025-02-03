<?php

namespace Lab404\Impersonate\Services;

use Exception;
use Illuminate\Foundation\Application;
use Lab404\Impersonate\Events\LeaveImpersonation;
use Lab404\Impersonate\Events\TakeImpersonation;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Contracts\Auth\Authenticatable;

class ImpersonateManager
{
    /** @var Application $app */
    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * @param  int  $id
     * @return Authenticatable
 */
    public function findUserById($id)
    {
        $user = $this->app['auth']->getProvider()->retrieveById($id);

        if ($user) {
            return $user;
        }

        throw (new ModelNotFoundException)
            ->setModel(Authenticatable::class, $id);
    }

    /**
     * @return bool
     */
    public function isImpersonating()
    {
        return session()->has($this->getSessionKey());
    }

    /**
     * @return  int|null
     */
    public function getImpersonatorId()
    {
        return session($this->getSessionKey(), null);
    }

    /**
     * @param Authenticatable $from
     * @param Authenticatable $to
     * @return bool
     */
    public function take($from, $to)
    {
        try {
            session()->put($this->getSessionKey(), $from->getKey());

            $this->app['auth']->quietLogout();
            $this->app['auth']->quietLogin($to);

        } catch (Exception $e) {
            unset($e);
            return false;
        }

        $this->app['events']->dispatch(new TakeImpersonation($from, $to));

        return true;
    }

    public function leave(): bool
    {
        try {
            $impersonated = $this->app['auth']->user();
            $impersonator = $this->findUserById($this->getImpersonatorId());

            $this->app['auth']->quietLogout();
            $this->app['auth']->quietLogin($impersonator);
            
            $this->clear();

        } catch (Exception $e) {
            unset($e);
            return false;
        }

        $this->app['events']->dispatch(new LeaveImpersonation($impersonator, $impersonated));

        return true;
    }

    /**
     * @return void
     */
    public function clear()
    {
        session()->forget($this->getSessionKey());
    }

    public function getSessionKey(): string
    {
        return config('laravel-impersonate.session_key');
    }

    public function getTakeRedirectTo(): string
    {
        try {
            $uri = route(config('laravel-impersonate.take_redirect_to'));
        } catch (\InvalidArgumentException $e) {
            $uri = config('laravel-impersonate.take_redirect_to');
        }

        return $uri;
    }

    public function getLeaveRedirectTo(): string
    {
        try {
            $uri = route(config('laravel-impersonate.leave_redirect_to'));
        } catch (\InvalidArgumentException $e) {
            $uri = config('laravel-impersonate.leave_redirect_to');
        }

        return $uri;
    }
}
