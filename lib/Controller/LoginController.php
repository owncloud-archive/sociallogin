<?php

namespace OCA\SocialLogin\Controller;

use OC\Authentication\Token\IToken;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\IL10N;
use OCP\ILogger;
use OCP\IRequest;
use OCP\IConfig;
use OCP\IUser;
use OCP\IUserSession;
use OCP\IUserManager;
use OCP\IURLGenerator;
use OCP\IAvatarManager;
use OCP\IGroupManager;
use OCP\ISession;
use OC\User\LoginException;
use OCA\SocialLogin\Storage\SessionStorage;
use OCA\SocialLogin\Provider\CustomOAuth2;
use OCA\SocialLogin\Provider\CustomOpenIDConnect;
use OCA\SocialLogin\Db\SocialConnectDAO;
use Hybridauth\Provider;
use Hybridauth\User\Profile;
use Hybridauth\HttpClient\Curl;
use Hybridauth\Data;

class LoginController extends Controller
{
    /** @var IConfig */
    private $config;
    /** @var IURLGenerator */
    private $urlGenerator;
    /** @var SessionStorage */
    private $storage;
    /** @var IUserManager */
    private $userManager;
    /** @var IUserSession */
    private $userSession;
    /** @var IAvatarManager */
    private $avatarManager;
    /** @var IGroupManager */
    private $groupManager;
    /** @var ISession */
    private $session;
    /** @var IL10N */
    private $l;
    /** @var SocialConnectDAO */
    private $socialConnect;
	/** @var ILogger */
	private $logger;

	public function __construct(
        $appName,
        IRequest $request,
        IConfig $config,
        IURLGenerator $urlGenerator,
        SessionStorage $storage,
        IUserManager $userManager,
        IUserSession $userSession,
        IAvatarManager $avatarManager,
        IGroupManager $groupManager,
        ISession $session,
        IL10N $l,
        SocialConnectDAO $socialConnect,
		ILogger $logger
    ) {
        parent::__construct($appName, $request);
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->storage = $storage;
        $this->userManager = $userManager;
        $this->userSession = $userSession;
        $this->avatarManager = $avatarManager;
        $this->groupManager = $groupManager;
        $this->session = $session;
        $this->l = $l;
        $this->socialConnect = $socialConnect;
		$this->logger = $logger;
	}

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function oauth($provider)
    {
        $scopes = [
            'facebook' => 'email, public_profile',
        ];
        $config = [];
        $providers = json_decode($this->config->getAppValue($this->appName, 'oauth_providers', '[]'), true);
        if (is_array($providers) && in_array($provider, array_keys($providers))) {
            foreach ($providers as $name => $prov) {
                if ($name === $provider) {
                    $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.oauth', ['provider' => $provider]);
                    $config = [
                        'callback' => $callbackUrl,
                        'keys'     => [
                            'id'     => $prov['appid'],
                            'secret' => $prov['secret'],
                        ],
                    ];
                    if (isset($scopes[$provider])) {
                        $config['scope'] = $scopes[$provider];
                    }
                    if (isset($prov['auth_params']) && is_array($prov['auth_params'])) {
                        foreach ($prov['auth_params'] as $k => $v) {
                            if (!empty($v)) {
                                $config['authorize_url_parameters'][$k] = $v;
                            }
                        }
                    }
                    break;
                }
            }
        }
        return $this->auth(Provider::class.'\\'.ucfirst($provider), $config, $provider, 'OAuth');
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function openid($provider)
    {
        $config = [];
        $providers = json_decode($this->config->getAppValue($this->appName, 'openid_providers', '[]'), true);
        if (is_array($providers)) {
            foreach ($providers as $prov) {
                if ($prov['name'] === $provider) {
                    $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.openid', ['provider' => $provider]);
                    $config = [
                        'callback'          => $callbackUrl,
                        'openid_identifier' => $prov['url'],
                    ];
                    break;
                }
            }
        }
        return $this->auth(Provider\OpenID::class, $config, $provider, 'OpenID');
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function customOidc($provider)
    {
        $config = [];
        $providers = json_decode($this->config->getAppValue($this->appName, 'custom_oidc_providers', '[]'), true);
        if (is_array($providers)) {
            foreach ($providers as $prov) {
                if ($prov['name'] === $provider) {
                    $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.custom_oidc', ['provider' => $provider]);
                    $config = [
                        'callback' => $callbackUrl,
                        'scope' => $prov['scope'],
                        'keys' => [
                            'id'     => $prov['clientId'],
                            'secret' => $prov['clientSecret'],
                        ],
                        'endpoints' => new Data\Collection([
                            'authorize_url'    => $prov['authorizeUrl'],
                            'access_token_url' => $prov['tokenUrl'],
                            'user_info_url'    => $prov['userInfoUrl'],
                            'api_base_url'     => '',
                        ]),
						'id.scope' => $prov['idScope'] ?? null
					];
                    break;
                }
            }
        }
        return $this->auth(CustomOpenIDConnect::class, $config, $provider, 'OpenID Connect');
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function customOauth2($provider)
    {
        $config = [];
        $providers = json_decode($this->config->getAppValue($this->appName, 'custom_oauth2_providers', '[]'), true);
        if (is_array($providers)) {
            foreach ($providers as $prov) {
                if ($prov['name'] === $provider) {
                    $callbackUrl = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.custom_oauth2', ['provider' => $provider]);
                    $config = [
                        'callback' => $callbackUrl,
                        'scope' => $prov['scope'],
                        'keys' => [
                            'id'     => $prov['clientId'],
                            'secret' => $prov['clientSecret'],
                        ],
                        'endpoints' => new Data\Collection([
                            'api_base_url'     => $prov['apiBaseUrl'],
                            'authorize_url'    => $prov['authorizeUrl'],
                            'access_token_url' => $prov['tokenUrl'],
                            'profile_url'      => $prov['profileUrl'],
                        ]),
                        'profile_fields'   => $prov['profileFields'],
					];
                    break;
                }
            }
        }
        return $this->auth(CustomOAuth2::class, $config, $provider, 'Custom OAuth2');
    }

    private function auth($class, array $config, $provider, $providerTitle)
    {
        if (empty($config)) {
            throw new LoginException($this->l->t('Unknown %s provider: "%s"', [$providerTitle, $provider]));
        }
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            $this->session->set('login_redirect_url', $redirectUrl);
        }
        try {
            $adapter = new $class($config, null, $this->storage);
            $adapter->authenticate();
            /** @var Profile $profile */
            $profile = $adapter->getUserProfile($config['id.scope'] ?? null);
        }  catch (\Exception $e) {
            throw new LoginException($e->getMessage());
        }
		$profileId = preg_replace('#.*/#', '', rtrim($profile->identifier, '/'));
        if (empty($profileId)) {
            throw new LoginException($this->l->t('Can not get identifier from provider'));
        }
        $uid = $provider.'-'.$profileId;
        if (strlen($uid) > 64) {
            $uid = $provider.'-'.md5($profileId);
        }
        return $this->login($uid, $profile, $config['id.scope']);
    }

	/**
	 * @param $samlNameId
	 * @return array [string uid, UserInterface backend]
	 */
	private function determineBackendFor($samlNameId) {
		foreach ($this->userManager->getBackends() as $backend) {
			$class = get_class($backend);
			$this->logger->debug(
				"Searching Backend $class for $samlNameId", ['app' => __CLASS__]
			);
			$userIds = $backend->getUsers($samlNameId, 2);
			switch (count($userIds)) {
				case 0:
					$this->logger->debug(
						"Backend $class returned no matching user for $samlNameId",
						['app' => __CLASS__]
					);
					break;
				case 1:
					$uid = array_pop($userIds);
					$this->logger->debug(
						"Backend $class returned $uid for $samlNameId",
						['app' => __CLASS__]
					);
					// Found the user in a different backend
					return [$uid, $backend];
				default:
					throw new \InvalidArgumentException("Backend $class returned more than one user for $samlNameId: " . implode(', ', $userIds));
			}
		}
		return [];
	}


	private function login($uid, Profile $profile, $idScope = null)
    {
    	if ($idScope !== null && isset($profile->data[$idScope])) {
			$user = $this->determineBackendFor($profile->data[$idScope]);
			if ($user === null) {
				throw new \Exception("No user known for id scope {$profile->data[$idScope]}");
			}
			$uid = $user[0];
		}
		$user = $this->userManager->get($uid);
        if (null === $user) {
            $connectedUid = $this->socialConnect->findUID($uid);
            $user = $this->userManager->get($connectedUid);
        }
        if ($this->userSession->isLoggedIn()) {
            if (!$this->config->getAppValue($this->appName, 'allow_login_connect')) {
                throw new LoginException($this->l->t('Social login connect is disabled'));
            }
            if (null !== $user) {
                throw new LoginException($this->l->t('This account already connected'));
            }
            $currentUid = $this->userSession->getUser()->getUID();
            $this->socialConnect->connectLogin($currentUid, $uid);
            return new RedirectResponse($this->urlGenerator->linkToRoute('settings.SettingsPage.getPersonal', ['sectionid'=>'security']));
        }
        if (null === $user) {
            if ($this->config->getAppValue($this->appName, 'disable_registration')) {
                throw new LoginException($this->l->t('Auto creating new users is disabled'));
            }
            if (
                $this->config->getAppValue($this->appName, 'prevent_create_email_exists')
                && count($this->userManager->getByEmail($profile->email)) !== 0
            ) {
                throw new LoginException($this->l->t('Email already registered'));
            }
            $password = substr(base64_encode(random_bytes(64)), 0, 30);
            $user = $this->userManager->createUser($uid, $password);
            $user->setDisplayName((string)$profile->displayName);
            $user->setEMailAddress((string)$profile->email);

            $newUserGroup = $this->config->getAppValue($this->appName, 'new_user_group');
            if ($newUserGroup) {
                try {
                    $group = $this->groupManager->get($newUserGroup);
                    $group->addUser($user);
                } catch (\Exception $e) {}
            }

            if ($profile->photoURL) {
                $curl = new Curl();
                $photo = $curl->request($profile->photoURL);
                try {
                    $avatar = $this->avatarManager->getAvatar($uid);
                    $avatar->set($photo);
                } catch (\Exception $e) {}
            }
            $this->config->setUserValue($uid, $this->appName, 'disable_password_confirmation', 1);
        }

        $this->completeLogin($user, ['loginName' => $user->getUID(), 'password' => null]);
        $this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());

        if ($redirectUrl = $this->session->get('login_redirect_url')) {
            return new RedirectResponse($redirectUrl);
        }

        $this->session->set('last-password-confirm', time());

        return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
    }

    private function getClientName() {
        $userAgent = $this->request->getHeader('USER_AGENT');
        return $userAgent !== null ? $userAgent : 'unknown';
    }

	/**
	 * @param IUser $user
	 * @param array $loginDetails
	 * @param bool $regenerateSessionId
	 * @return true returns true if login successful or an exception otherwise
	 * @throws LoginException
	 */
	public function completeLogin(IUser $user, array $loginDetails, $regenerateSessionId = true) {
		if (!$user->isEnabled()) {
			// disabled users can not log in
			// injecting l10n does not work - there is a circular dependency between session and \OCP\L10N\IFactory
			$message = \OC::$server->getL10N('lib')->t('User disabled');
			throw new LoginException($message);
		}
		if($regenerateSessionId) {
			$this->session->regenerateId();
		}
		$this->userSession->setUser($user);
//		$this->userSession->setLoginName($loginDetails['loginName']);
		if(isset($loginDetails['token']) && $loginDetails['token'] instanceof IToken) {
//			$this->userSession->setToken($loginDetails['token']->getId());
			$firstTimeLogin = false;
		} else {
//			$this->userSession->setToken(null);
			$firstTimeLogin = $user->updateLastLoginTimestamp();
		}
		$this->userManager->emit('\OC\User', 'postLogin', [$user, $loginDetails['password']]);
		if($this->userSession->isLoggedIn()) {
			$this->userSession->prepareUserLogin($firstTimeLogin, $regenerateSessionId);
			return true;
		}
		$message = \OC::$server->getL10N('lib')->t('Login canceled by app');
		throw new LoginException($message);
	}
}
