//! The XAML easing functions, with the formulas and default parameters of
//! microsoft-ui-xaml's `dxaml/xcp/components/animation/EasingFunctions.cpp`
//! and `dxaml/xcp/core/inc/EasingFunctions.h`.

use std::f32::consts::{E, PI};

/// `EasingFunctionBase.EasingMode`; XAML's default is [`EasingMode::Out`]
/// (EasingFunctions.h:56).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EasingMode {
    In,
    #[default]
    Out,
    InOut,
}

/// One XAML easing function and its parameters.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Easing {
    /// BackEase: t³ − t·A·sin(πt).
    Back { amplitude: f32 },
    /// BounceEase: parabolic bounces over a geometric series.
    Bounce { bounces: i32, bounciness: f32 },
    /// CircleEase: 1 − √(1 − t²).
    Circle,
    /// CubicEase: t³.
    Cubic,
    /// ElasticEase: an exponentially growing sine.
    Elastic { oscillations: i32, springiness: f32 },
    /// ExponentialEase: (e^{kt} − 1)/(e^k − 1).
    Exponential { exponent: f32 },
    /// PowerEase: t^P.
    Power { power: f32 },
    /// QuadraticEase: t².
    Quadratic,
    /// QuarticEase: t⁴.
    Quartic,
    /// QuinticEase: t⁵.
    Quintic,
    /// SineEase: 1 − sin((1 − t)·π/2).
    Sine,
}

impl Easing {
    /// The eleven XAML easings with their default parameters
    /// (EasingFunctions.h, DependencyProperty.cpp): Back amplitude 1,
    /// Bounce 3 bounces of bounciness 2, Elastic 3 oscillations of
    /// springiness 3, Exponential exponent 2, Power 2.
    pub const ALL: [(&'static str, Easing); 11] = [
        ("BackEase", Easing::Back { amplitude: 1. }),
        (
            "BounceEase",
            Easing::Bounce {
                bounces: 3,
                bounciness: 2.,
            },
        ),
        ("CircleEase", Easing::Circle),
        ("CubicEase", Easing::Cubic),
        (
            "ElasticEase",
            Easing::Elastic {
                oscillations: 3,
                springiness: 3.,
            },
        ),
        ("ExponentialEase", Easing::Exponential { exponent: 2. }),
        ("PowerEase", Easing::Power { power: 2. }),
        ("QuadraticEase", Easing::Quadratic),
        ("QuarticEase", Easing::Quartic),
        ("QuinticEase", Easing::Quintic),
        ("SineEase", Easing::Sine),
    ];

    /// `EaseInCore`: the curve for [`EasingMode::In`].
    pub fn ease_in(self, t: f32) -> f32 {
        const EPSILON: f32 = 1e-4;
        match self {
            Easing::Back { amplitude } => {
                let t = t.max(0.);
                t * t * t - t * amplitude * (t * PI).sin()
            }
            Easing::Bounce {
                bounces,
                bounciness,
            } => bounce_in(t, bounces, bounciness),
            Easing::Circle => {
                let t = t.clamp(-1., 1.);
                1. - (1. - t * t).sqrt()
            }
            Easing::Cubic => t * t * t,
            Easing::Elastic {
                oscillations,
                springiness,
            } => {
                let n = oscillations.max(0) as f32;
                let modifier = if springiness.abs() <= EPSILON {
                    t
                } else {
                    (E.powf(springiness * t) - 1.) / (E.powf(springiness) - 1.)
                };
                modifier * (t * (2. * PI * n + PI / 2.)).sin()
            }
            Easing::Exponential { exponent } => {
                if exponent.abs() <= EPSILON {
                    t
                } else {
                    (E.powf(exponent * t) - 1.) / (E.powf(exponent) - 1.)
                }
            }
            Easing::Power { power } => t.powf(power.max(0.)),
            Easing::Quadratic => t * t,
            Easing::Quartic => t * t * t * t,
            Easing::Quintic => t * t * t * t * t,
            Easing::Sine => 1. - ((1. - t) * (PI / 2.)).sin(),
        }
    }

    /// The eased progress for `t` in 0..=1 (EasingFunctions.cpp:57-86):
    /// In is the core curve, Out mirrors it, InOut runs In then Out.
    pub fn ease(self, mode: EasingMode, t: f32) -> f32 {
        let t = t.clamp(0., 1.);
        match mode {
            EasingMode::In => self.ease_in(t),
            EasingMode::Out => 1. - self.ease_in(1. - t),
            EasingMode::InOut => {
                if t < 0.5 {
                    self.ease_in(t * 2.) / 2.
                } else {
                    (1. - self.ease_in(2. - t * 2.)) / 2. + 0.5
                }
            }
        }
    }
}

/// `CBounceInterpolator::EaseInCore`.
fn bounce_in(t: f32, bounces: i32, bounciness: f32) -> f32 {
    let bounces = bounces.max(0) as f32;
    let bounciness = if bounciness <= 1. + 1e-4 {
        1.01
    } else {
        bounciness
    };
    let pow = bounciness.powf(bounces);
    let one_minus = 1. - bounciness;
    let sum_of_units = (1. - pow) / one_minus + pow / 2.;
    let unit_at_t = t * sum_of_units;
    let bounce_at_t =
        ((-unit_at_t * (1. - bounciness) + 1.) as f64).ln() / (bounciness as f64).ln();
    let start = (bounce_at_t as f32).floor();
    let end = start + 1.;
    let start_time = (1. - bounciness.powf(start)) / (one_minus * sum_of_units);
    let end_time = (1. - bounciness.powf(end)) / (one_minus * sum_of_units);
    let mid_time = (start_time + end_time) / 2.;
    let relative = t - mid_time;
    let radius = mid_time - start_time;
    let amplitude = (1. / bounciness).powf(bounces - start);
    (-amplitude / (radius * radius)) * (relative - radius) * (relative + radius)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_easing_starts_at_zero_and_ends_at_one_in_every_mode() {
        for (name, easing) in Easing::ALL {
            for mode in [EasingMode::In, EasingMode::Out, EasingMode::InOut] {
                assert!(easing.ease(mode, 0.).abs() < 1e-3, "{name} {mode:?} at 0");
                assert!(
                    (easing.ease(mode, 1.) - 1.).abs() < 1e-3,
                    "{name} {mode:?} at 1"
                );
            }
        }
    }

    #[test]
    fn easings_match_the_xaml_formulas() {
        assert!((Easing::Quadratic.ease(EasingMode::In, 0.5) - 0.25).abs() < 1e-6);
        assert!((Easing::Cubic.ease(EasingMode::Out, 0.5) - 0.875).abs() < 1e-6);
        // Back overshoots below zero on the way in.
        assert!(Easing::Back { amplitude: 1. }.ease(EasingMode::In, 0.3) < 0.);
        // Elastic Out overshoots past one.
        let elastic = Easing::Elastic {
            oscillations: 3,
            springiness: 3.,
        };
        assert!((0..100).any(|i| elastic.ease(EasingMode::Out, i as f32 / 100.) > 1.));
        // Bounce In touches zero between bounces and stays within 0..=1.
        let bounce = Easing::Bounce {
            bounces: 3,
            bounciness: 2.,
        };
        for i in 0..=100 {
            let v = bounce.ease(EasingMode::In, i as f32 / 100.);
            assert!((-1e-3..=1. + 1e-3).contains(&v), "bounce {i}: {v}");
        }
        // InOut is symmetric about the middle.
        let sine = Easing::Sine;
        assert!((sine.ease(EasingMode::InOut, 0.5) - 0.5).abs() < 1e-6);
    }
}
