// (C) Copyright IBM Deutschland GmbH 2021, 2023
// (C) Copyright IBM Corp 2021, 2023
//
// non-exclusively licensed to gematik GmbH

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pipeline {
    agent {
        node {
            label 'master'
        }
    }
    options {
        disableConcurrentBuilds()
        skipDefaultCheckout()
    }
    environment {
        ENABLE_GRADLE_BUILD_CACHE = 'true'
        ENABLE_GRADLE_CONFIG_CACHE = 'true' // gradle 6+
        WARN_GRADLE_CONFIG_CACHE_PROBLEMS = 'true' // do not fail builds for config cache unsupported tasks
    }
    stages {
        stage('Checkout') {
            steps {
                cleanWs()
                commonCheckout()
            }
        }

        stage('Create Release') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                gradleCreateReleaseEpa()
            }
        }

        stage('Check Container Build') {
            when {
                not {
                    anyOf {
                        branch 'master'
                        branch 'release/*'
                    }
                }
            }
            steps {
                loadNexusConfiguration {
                    withCredentials(
                        [usernamePassword(credentialsId: 'jenkins-github-erp', usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
                    ){
                        checkDockerBuild(
                            DOCKER_OPTS:'--build-arg NEXUS_USERNAME="${NEXUS_USERNAME}" --build-arg NEXUS_PASSWORD="${NEXUS_PASSWORD}"',
                            DOCKER_FILE:'docker/Dockerfile'
                        )
                    }
                }
            }
        }

        stage('Build Container') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                loadNexusConfiguration {
                    withCredentials(
                        [usernamePassword(credentialsId: 'jenkins-github-erp', usernameVariable: 'GITHUB_USERNAME', passwordVariable: 'GITHUB_OAUTH_TOKEN')]
                    ){
                        buildAndPushContainer(
                            DOCKER_OPTS:'--build-arg NEXUS_USERNAME="${NEXUS_USERNAME}" --build-arg NEXUS_PASSWORD="${NEXUS_PASSWORD}"',
                            DOCKER_FILE:'docker/Dockerfile'
                        )
                    }
                }
            }
        }

        stage('Publish Release') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                finishRelease()
            }
        }

        stage ("Publish to Nexus") {
            agent {
                docker {
                    label 'dockerstage'
                    image 'conanio/gcc10:latest'
                    reuseNode true
                    args '-u root:sudo'
                }
            }
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                script {
                    loadNexusConfiguration {
                        sh '''
                            git config --global --add safe.directory '*'
                            conan remote clean &&\
                            conan remote add erp https://nexus.epa-dev.net/repository/erp-conan-internal true --force &&\
                            conan user -r erp -p "${NEXUS_PASSWORD}" "${NEXUS_USERNAME}" &&\
                            conan export . &&\
                            conan export . tpmclient/latest@_/_ &&\
                            conan upload --remote erp --confirm tpmclient
                        '''
                    }
                }
            }
        }

        stage('Deployment to dev') {
            when {
                anyOf {
                    branch 'master'
                    branch 'release/*'
                }
            }
            steps {
                script {
                    if (env.BRANCH_NAME == 'master') {
                        triggerDeployment('targetEnvironment': 'dev2')
                    } else if (env.BRANCH_NAME.startsWith('release/1.0.')) {
                        triggerDeployment('targetEnvironment': 'dev')
                    }
                }
            }
        }
    }
}
