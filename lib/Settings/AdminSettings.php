<?php

namespace OCA\SocialLogin\Settings;

use OCP\AppFramework\Http\TemplateResponse;
use OCP\Settings\ISettings;
use OCP\IGroupManager;
use OCP\IURLGenerator;
use OCP\IConfig;
use OCP\Template;
use OCP\Util;

class AdminSettings implements ISettings
{
    /** @var string */
    private $appName;
    /** @var IConfig */
    private $config;
    /** @var IURLGenerator */
    private $urlGenerator;
    /** @var IGroupManager */
    private $groupManager;

    public function __construct($appName, IConfig $config, IURLGenerator $urlGenerator, IGroupManager $groupManager)
    {
        $this->appName = $appName;
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->groupManager = $groupManager;
    }

	/**
	 * The panel controller method that returns a template to the UI
	 *
	 * @since 10.0
	 * @return TemplateResponse | Template
	 */
	public function getPanel() {
        Util::addStyle($this->appName, 'settings');
        Util::addScript($this->appName, 'settings');
        $paramsNames = [
            'new_user_group',
            'disable_registration',
            'allow_login_connect',
            'prevent_create_email_exists',
        ];
        $oauthProviders = [
            'google',
            'facebook',
            'twitter',
            'GitHub',
            'discord',
        ];
        $groupNames = [];
        $groups = $this->groupManager->search('');
        foreach ($groups as $group) {
            $groupNames[] = $group->getGid();
        }
        $providers = [];
        $savedProviders = json_decode($this->config->getAppValue($this->appName, 'oauth_providers', '[]'), true);
        foreach ($oauthProviders as $provider) {
            if (array_key_exists($provider, $savedProviders)) {
                $providers[$provider] = $savedProviders[$provider];
            } else {
                $providers[$provider] = [
                    'appid' => '',
                    'secret' => '',
                ];
            }
        }
        $openIdProviders = json_decode($this->config->getAppValue($this->appName, 'openid_providers', '[]'), true);
        if (!is_array($openIdProviders)) {
            $openIdProviders = [];
        }
        $custom_oidcProviders = json_decode($this->config->getAppValue($this->appName, 'custom_oidc_providers', '[]'), true);
        if (!is_array($custom_oidcProviders)) {
            $custom_oidcProviders = [];
        }
        $custom_oauth2Providers = json_decode($this->config->getAppValue($this->appName, 'custom_oauth2_providers', '[]'), true);
        if (!is_array($custom_oauth2Providers)) {
            $custom_oauth2Providers = [];
        }

		$template = new Template($this->appName, 'admin');
		$template->assign('action_url',  $this->urlGenerator->linkToRoute($this->appName.'.settings.saveAdmin'));
            $template->assign('groups', $groupNames);
            $template->assign('providers', $providers);
            $template->assign('openid_providers', $openIdProviders);
            $template->assign('custom_oidc_providers', $custom_oidcProviders);
            $template->assign('custom_oauth2_providers', $custom_oauth2Providers);
        foreach ($paramsNames as $paramName) {
			$template->assign($paramName, $this->config->getAppValue($this->appName, $paramName));
        }
        return $template;
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
}
