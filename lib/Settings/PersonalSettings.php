<?php

namespace OCA\SocialLogin\Settings;

use OCA\SocialLogin\Db\SocialConnectDAO;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IUserSession;
use OCP\Settings\ISettings;
use OCP\IGroupManager;
use OCP\IURLGenerator;
use OCP\IConfig;
use OCP\Template;
use OCP\Util;

class PersonalSettings implements ISettings
{
    /** @var string */
    private $appName;
    /** @var IConfig */
    private $config;
    /** @var IURLGenerator */
    private $urlGenerator;
	/**
	 * @var IUserSession
	 */
	private $userSession;
	/**
	 * @var SocialConnectDAO
	 */
	private $socialConnect;

	public function __construct($appName, IConfig $config,
								IURLGenerator $urlGenerator,
								IUserSession $userSession,
								SocialConnectDAO $socialConnect)
    {
        $this->appName = $appName;
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
		$this->userSession = $userSession;
		$this->socialConnect = $socialConnect;
	}

	/**
	 * The panel controller method that returns a template to the UI
	 *
	 * @since 10.0
	 * @return TemplateResponse | Template
	 */
	public function getPanel() {
		Util::addScript($this->appName, 'personal');
		$uid = $this->userSession->getUser()->getUID();
		$params = [
			'providers' => [],
			'connected_logins' => [],
			'action_url' => $this->urlGenerator->linkToRoute($this->appName.'.settings.savePersonal'),
			'allow_login_connect' => $this->config->getAppValue($this->appName, 'allow_login_connect', false),
			'disable_password_confirmation' => $this->config->getUserValue($uid, $this->appName, 'disable_password_confirmation', false),
		];
		if ($params['allow_login_connect']) {
			$providers = json_decode($this->config->getAppValue($this->appName, 'oauth_providers', '[]'), true);
			if (is_array($providers)) {
				foreach ($providers as $name => $provider) {
					if ($provider['appid']) {
						$params['providers'][ucfirst($name)] = $this->urlGenerator->linkToRoute($this->appName.'.login.oauth', ['provider' => $name]);
					}
				}
			}
			$params['providers'] = array_merge($params['providers'], $this->getProviders('openid'));
			$params['providers'] = array_merge($params['providers'], $this->getProviders('custom_oidc'));
			$params['providers'] = array_merge($params['providers'], $this->getProviders('custom_oauth2'));

			$connectedLogins = $this->socialConnect->getConnectedLogins($uid);
			foreach ($connectedLogins as $login) {
				$params['connected_logins'][$login] = $this->urlGenerator->linkToRoute($this->appName.'.settings.disconnectSocialLogin', [
					'login' => $login,
					'requesttoken' => Util::callRegister(),
				]);
			}
		}
		return new TemplateResponse($this->appName, 'personal', $params, '');
    }

    public function getPriority()
    {
        return 0;
    }


	/**
	 * A string to identify the section in the UI / HTML and URL
	 *
	 * @since 10.0
	 * @return string
	 */
	public function getSectionID() {
		return 'security';
	}

	private function getProviders($providersType)
	{
		$result = [];
		$providers = json_decode($this->config->getAppValue($this->appName, $providersType.'_providers', '[]'), true);
		if (is_array($providers)) {
			foreach ($providers as $provider) {
				$name = $provider['name'];
				$title = $provider['title'];
				$result[$title] = $this->urlGenerator->linkToRoute($this->appName.'.login.'.$providersType, ['provider' => $name]);
			}
		}
		return $result;
	}

}
