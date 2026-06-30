/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with ata
 */
@java.lang.SuppressWarnings("unused")
public final class AtaDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ata_eh_qc_complete(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ata_ehi_push_desc($arg1, (const u8 *)$arg2, $arg3_)")
  public static void __ata_ehi_push_desc(Ptr<ata_eh_info> ehi, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ata_port_freeze(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __ata_qc_complete(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__ata_scsi_find_dev($arg1, (const struct scsi_device *)$arg2)")
  public static Ptr<ata_device> __ata_scsi_find_dev(Ptr<ata_port> ap, Ptr<scsi_device> scsidev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __ata_scsi_queuecmd(Ptr<scsi_cmnd> scmd, Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int __ata_sff_port_intr(Ptr<ata_port> ap, Ptr<ata_queued_cmd> qc,
      boolean hsmv_on_idle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_acpi_ap_notify_dock(Ptr<acpi_device> adev, @Unsigned int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_ap_uevent(Ptr<acpi_device> adev, @Unsigned int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_bind_dev(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_bind_port(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_acpi_cbl_pata_type(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_acpi_dev_notify_dock(Ptr<acpi_device> adev, @Unsigned int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_dev_uevent(Ptr<acpi_device> adev, @Unsigned int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_dissociate(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_acpi_gtf_to_tf($arg1, (const struct ata_acpi_gtf *)$arg2, $arg3)")
  public static void ata_acpi_gtf_to_tf(Ptr<ata_device> dev, Ptr<ata_acpi_gtf> gtf,
      Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_acpi_gtm_xfermask($arg1, (const struct ata_acpi_gtm *)$arg2)")
  public static @Unsigned int ata_acpi_gtm_xfermask(Ptr<ata_device> dev, Ptr<ata_acpi_gtm> gtm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_handle_hotplug(Ptr<ata_port> ap, Ptr<ata_device> dev,
      @Unsigned int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_acpi_on_devcfg(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_on_disable(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_on_resume(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_acpi_run_tf($arg1, (const struct ata_acpi_gtf *)$arg2, (const struct ata_acpi_gtf *)$arg3)")
  public static int ata_acpi_run_tf(Ptr<ata_device> dev, Ptr<ata_acpi_gtf> gtf,
      Ptr<ata_acpi_gtf> prev_gtf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_acpi_set_state(Ptr<ata_port> ap,
      @OriginalName("pm_message_t") pm_message state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_acpi_stm($arg1, (const struct ata_acpi_gtm *)$arg2)")
  public static int ata_acpi_stm(Ptr<ata_port> ap, Ptr<ata_acpi_gtm> stm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_transport_template> ata_attach_transport() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static ata_completion_errors ata_bmdma_dumb_qc_prep(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_bmdma_error_handler(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn ata_bmdma_interrupt(int irq,
      Ptr<?> dev_instance) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_bmdma_irq_clear(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_bmdma_nodma($arg1, (const u8 *)$arg2)")
  public static void ata_bmdma_nodma(Ptr<ata_host> host, String reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_bmdma_port_intr(Ptr<ata_port> ap, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_bmdma_port_start(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_bmdma_port_start32(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_bmdma_post_internal_cmd(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_bmdma_qc_issue(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static ata_completion_errors ata_bmdma_qc_prep(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_bmdma_setup(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_bmdma_start(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char ata_bmdma_status(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_bmdma_stop(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_build_rw_tf(Ptr<ata_queued_cmd> qc, @Unsigned long block,
      @Unsigned int n_block, @Unsigned int tf_flags, int cdl, int _class) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_cable_40wire(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_cable_80wire(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_cable_ignore(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_cable_sata(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_cable_unknown(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_change_queue_depth(Ptr<ata_port> ap, Ptr<scsi_device> sdev,
      int queue_depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_cmd_ioctl(Ptr<scsi_device> scsidev, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("acpi_handle") Ptr<?> ata_dev_acpi_handle(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_dev_classify((const struct ata_taskfile *)$arg1)")
  public static @Unsigned int ata_dev_classify(Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_config_cdl(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_config_cpr(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_config_lpm(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_dev_config_ncq(Ptr<ata_device> dev, String desc, @Unsigned long desc_sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_config_ncq_non_data(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_config_ncq_send_recv(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_dev_configure(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_disable(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_free_resources(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_dev_get_GTF(Ptr<ata_device> dev, Ptr<Ptr<ata_acpi_gtf>> gtf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_init(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ata_device> ata_dev_next(Ptr<ata_device> dev, Ptr<ata_link> link,
      ata_dev_iter_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ata_device> ata_dev_pair(Ptr<ata_device> adev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ata_link> ata_dev_phys_link(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_dev_power_init_tf(Ptr<ata_device> dev, Ptr<ata_taskfile> tf,
      boolean set_active) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_dev_power_is_active(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_power_set_active(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_power_set_standby(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_dev_quirks((const struct ata_device *)$arg1)")
  public static @Unsigned int ata_dev_quirks(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_dev_read_id(Ptr<ata_device> dev, Ptr<java.lang. @Unsigned Integer> p_class,
      @Unsigned int flags, Ptr<java.lang. @Unsigned Short> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_dev_reread_id(Ptr<ata_device> dev, @Unsigned int readid_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_dev_revalidate(Ptr<ata_device> dev, @Unsigned int new_class,
      @Unsigned int readid_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_dev_same_device($arg1, $arg2, (const short unsigned int *)$arg3)")
  public static int ata_dev_same_device(Ptr<ata_device> dev, @Unsigned int new_class,
      Ptr<java.lang. @Unsigned Short> new_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_dev_set_feature(Ptr<ata_device> dev, char subcmd, char action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_dev_set_mode(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dev_xfermask(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_devchk(Ptr<ata_port> ap, @Unsigned int device) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_devres_release(Ptr<device> gendev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_do_dev_read_id(Ptr<ata_device> dev, Ptr<ata_taskfile> tf,
      Ptr<java.lang. @Unsigned @OriginalName("__le16") Short> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_do_link_abort(Ptr<ata_port> ap, Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_do_reset(Ptr<ata_link> link, @OriginalName("ata_reset_fn_t") Ptr<?> reset,
      Ptr<java.lang. @Unsigned Integer> classes, @Unsigned long deadline, boolean clear_classes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_down_xfermask_limit(Ptr<ata_device> dev, @Unsigned int sel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_dummy_error_handler(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_dummy_qc_issue(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_about_to_do(Ptr<ata_link> link, Ptr<ata_device> dev,
      @Unsigned int action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_acquire(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_analyze_ncq_error(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_eh_analyze_tf(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_autopsy(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_categorize_error(@Unsigned int eflags, @Unsigned int err_mask,
      Ptr<java.lang.Integer> xfer_ok) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_clear_action(Ptr<ata_link> link, Ptr<ata_device> dev,
      Ptr<ata_eh_info> ehi, @Unsigned int action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static scsi_disposition ata_eh_decide_disposition(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_detach_dev(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_dev_disable(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_done(Ptr<ata_link> link, Ptr<ata_device> dev, @Unsigned int action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_fastdrain_timerfn(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_finish(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_freeze_port(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_get_ncq_success_sense(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_get_success_sense(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_handle_dev_fail(Ptr<ata_device> dev, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_handle_port_resume(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_handle_port_suspend(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_link_autopsy(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_link_report(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_link_set_lpm(Ptr<ata_link> link, ata_lpm_policy policy,
      Ptr<Ptr<ata_device>> r_failed_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_maybe_retry_flush(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_park_issue_cmd(Ptr<ata_device> dev, int park) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_qc_complete(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_qc_retry(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_recover(Ptr<ata_port> ap, Ptr<ata_reset_operations> reset_ops,
      Ptr<Ptr<ata_link>> r_failed_link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_release(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_report(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_eh_request_sense(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_reset(Ptr<ata_link> link, int classify,
      Ptr<ata_reset_operations> reset_ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_revalidate_and_attach(Ptr<ata_link> link,
      Ptr<Ptr<ata_device>> r_failed_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_schedule_probe(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_scsidone(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_eh_set_mode(Ptr<ata_link> link, Ptr<Ptr<ata_device>> r_failed_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_eh_speed_down(Ptr<ata_device> dev, @Unsigned int eflags,
      @Unsigned int err_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_thaw_port(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_eh_unload(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_ehi_clear_desc(Ptr<ata_eh_info> ehi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_ehi_push_desc($arg1, (const u8 *)$arg2, $arg3_)")
  public static void ata_ehi_push_desc(Ptr<ata_eh_info> ehi, String fmt,
      java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_ering_map($arg1, (int (*)(struct ata_ering_entry*, void*))$arg2, $arg3)")
  public static int ata_ering_map(Ptr<ata_ering> ering, Ptr<?> map_fn, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_exec_internal($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static @Unsigned int ata_exec_internal(Ptr<ata_device> dev, Ptr<ata_taskfile> tf,
      Ptr<java.lang.Character> cdb, dma_data_direction dma_dir, Ptr<?> buf, @Unsigned int buflen,
      @Unsigned int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_finalize_port_ops(Ptr<ata_port_operations> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ata_device> ata_find_dev(Ptr<ata_port> ap, @Unsigned int devno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_force_cbl(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_force_link_limits(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_gen_ata_sense(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_gen_passthru_sense(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_generic_init_one($arg1, (const struct pci_device_id *)$arg2)")
  public static int ata_generic_init_one(Ptr<pci_dev> dev, Ptr<pci_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_generic_pci_driver_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_generic_pci_driver_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)ata_get_cmd_name($arg1))")
  public static String ata_get_cmd_name(char command) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_host_activate($arg1, $arg2, $arg3, $arg4, (const struct scsi_host_template *)$arg5)")
  public static int ata_host_activate(Ptr<ata_host> host, int irq,
      @OriginalName("irq_handler_t") Ptr<?> irq_handler, @Unsigned long irq_flags,
      Ptr<scsi_host_template> sht) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ata_host> ata_host_alloc(Ptr<device> dev, int n_ports) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_host_alloc_pinfo($arg1, (const const struct ata_port_info **)$arg2, $arg3)")
  public static Ptr<ata_host> ata_host_alloc_pinfo(Ptr<device> dev, Ptr<Ptr<ata_port_info>> ppi,
      int n_ports) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_host_detach(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_host_get(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_host_init(Ptr<ata_host> host, Ptr<device> dev,
      Ptr<ata_port_operations> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_host_put(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_host_register($arg1, (const struct scsi_host_template *)$arg2)")
  public static int ata_host_register(Ptr<ata_host> host, Ptr<scsi_host_template> sht) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_host_release(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_host_resume(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_host_start(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_host_stop(Ptr<device> gendev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_host_suspend(Ptr<ata_host> host,
      @OriginalName("pm_message_t") pm_message mesg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_hpa_resize(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_hsm_qc_complete(Ptr<ata_queued_cmd> qc, int in_wq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_id_c_string((const short unsigned int *)$arg1, $arg2, $arg3, $arg4)")
  public static void ata_id_c_string(Ptr<java.lang. @Unsigned Short> id, String s,
      @Unsigned int ofs, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_id_n_sectors((const short unsigned int *)$arg1)")
  public static @Unsigned long ata_id_n_sectors(Ptr<java.lang. @Unsigned Short> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_id_string((const short unsigned int *)$arg1, $arg2, $arg3, $arg4)")
  public static void ata_id_string(Ptr<java.lang. @Unsigned Short> id, String s, @Unsigned int ofs,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_id_xfermask((const short unsigned int *)$arg1)")
  public static @Unsigned int ata_id_xfermask(Ptr<java.lang. @Unsigned Short> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_identify_page_supported(Ptr<ata_device> dev, char page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_internal_cmd_timed_out(Ptr<ata_device> dev, char cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_internal_cmd_timeout(Ptr<ata_device> dev, char cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_link_abort(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_link_init(Ptr<ata_port> ap, Ptr<ata_link> link, int pmp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ata_link> ata_link_next(Ptr<ata_link> link, Ptr<ata_port> ap,
      ata_link_iter_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_link_nr_enabled(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_link_offline(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_link_online(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_log_supported(Ptr<ata_device> dev, char log) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)ata_mode_string($arg1))")
  public static String ata_mode_string(@Unsigned int xfer_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_mselect_control($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static int ata_mselect_control(Ptr<ata_queued_cmd> qc, char spg,
      Ptr<java.lang.Character> buf, int len, Ptr<java.lang. @Unsigned Short> fp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_msense_caching(Ptr<java.lang. @Unsigned Short> id,
      Ptr<java.lang.Character> buf, boolean changeable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_msense_control(Ptr<ata_device> dev, Ptr<java.lang.Character> buf,
      char spg, boolean changeable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_msense_control_spgt2(Ptr<ata_device> dev,
      Ptr<java.lang.Character> buf, char spg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_msleep(Ptr<ata_port> ap, @Unsigned int msecs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_ncq_prio_enable(Ptr<ata_port> ap, Ptr<scsi_device> sdev, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ata_ncq_prio_enable_show(Ptr<device> device,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_ncq_prio_enable_store($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long ata_ncq_prio_enable_store(Ptr<device> device,
      Ptr<device_attribute> attr, String buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_ncq_prio_enabled(Ptr<ata_port> ap, Ptr<scsi_device> sdev,
      Ptr<java.lang. @OriginalName("bool") Boolean> enabled) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_ncq_prio_supported(Ptr<ata_port> ap, Ptr<scsi_device> sdev,
      Ptr<java.lang. @OriginalName("bool") Boolean> supported) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ata_ncq_prio_supported_show(Ptr<device> device,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_pack_xfermask(@Unsigned int pio_mask, @Unsigned int mwdma_mask,
      @Unsigned int udma_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_parse_force_one($arg1, $arg2, (const u8**)$arg3)")
  public static int ata_parse_force_one(Ptr<String> cur, Ptr<ata_force_ent> force_ent,
      Ptr<String> reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_parse_force_param() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_pci_bmdma_clear_simplex(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_pci_bmdma_init(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_pci_bmdma_init_one($arg1, (const const struct ata_port_info **)$arg2, (const struct scsi_host_template *)$arg3, $arg4, $arg5)")
  public static int ata_pci_bmdma_init_one(Ptr<pci_dev> pdev, Ptr<Ptr<ata_port_info>> ppi,
      Ptr<scsi_host_template> sht, Ptr<?> host_priv, int hflags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_pci_bmdma_prepare_host($arg1, (const const struct ata_port_info **)$arg2, $arg3)")
  public static int ata_pci_bmdma_prepare_host(Ptr<pci_dev> pdev, Ptr<Ptr<ata_port_info>> ppi,
      Ptr<Ptr<ata_host>> r_host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_pci_device_do_resume(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_pci_device_do_suspend(Ptr<pci_dev> pdev,
      @OriginalName("pm_message_t") pm_message mesg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_pci_device_resume(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_pci_device_suspend(Ptr<pci_dev> pdev,
      @OriginalName("pm_message_t") pm_message mesg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_pci_init_one($arg1, (const const struct ata_port_info **)$arg2, (const struct scsi_host_template *)$arg3, $arg4, $arg5, $arg6)")
  public static int ata_pci_init_one(Ptr<pci_dev> pdev, Ptr<Ptr<ata_port_info>> ppi,
      Ptr<scsi_host_template> sht, Ptr<?> host_priv, int hflags, boolean bmdma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_pci_remove_one(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_pci_sff_activate_host($arg1, $arg2, (const struct scsi_host_template *)$arg3)")
  public static int ata_pci_sff_activate_host(Ptr<ata_host> host,
      @OriginalName("irq_handler_t") Ptr<?> irq_handler, Ptr<scsi_host_template> sht) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_pci_sff_init_host(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_pci_sff_init_one($arg1, (const const struct ata_port_info **)$arg2, (const struct scsi_host_template *)$arg3, $arg4, $arg5)")
  public static int ata_pci_sff_init_one(Ptr<pci_dev> pdev, Ptr<Ptr<ata_port_info>> ppi,
      Ptr<scsi_host_template> sht, Ptr<?> host_priv, int hflag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_pci_sff_prepare_host($arg1, (const const struct ata_port_info **)$arg2, $arg3)")
  public static int ata_pci_sff_prepare_host(Ptr<pci_dev> pdev, Ptr<Ptr<ata_port_info>> ppi,
      Ptr<Ptr<ata_host>> r_host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_pci_shutdown_one(Ptr<pci_dev> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_phys_link_offline(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_phys_link_online(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_pio_need_iordy((const struct ata_device *)$arg1)")
  public static @Unsigned int ata_pio_need_iordy(Ptr<ata_device> adev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_pio_sector(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_pio_sectors(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_pio_xfer(Ptr<ata_queued_cmd> qc, Ptr<page> page, @Unsigned int offset,
      @Unsigned long xfer_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_platform_remove_one(Ptr<platform_device> pdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_abort(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ata_port> ata_port_alloc(Ptr<ata_host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_port_classify($arg1, (const struct ata_taskfile *)$arg2)")
  public static @Unsigned int ata_port_classify(Ptr<ata_port> ap, Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_port_desc($arg1, (const u8 *)$arg2, $arg3_)")
  public static void ata_port_desc(Ptr<ata_port> ap, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_port_detach(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_port_free(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_freeze(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_port_pbar_desc($arg1, $arg2, $arg3, (const u8 *)$arg4)")
  public static void ata_port_pbar_desc(Ptr<ata_port> ap, int bar,
      @OriginalName("ssize_t") long offset, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_pm_freeze(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_pm_poweroff(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_pm_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_pm_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_port_probe(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_port_request_pm(Ptr<ata_port> ap,
      @OriginalName("pm_message_t") pm_message mesg, @Unsigned int action, @Unsigned int ehi_flags,
      boolean async) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_runtime_idle(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_runtime_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_port_runtime_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_port_schedule_eh(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_port_wait_eh(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_qc_complete(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_qc_complete_internal(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_qc_complete_multiple(Ptr<ata_port> ap, @Unsigned long qc_active) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_qc_free(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ata_qc_get_active(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_qc_issue(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_qc_schedule_eh(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_ratelimit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_read_log_page(Ptr<ata_device> dev, char log, char page,
      Ptr<?> buf, @Unsigned int sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_release_transport(Ptr<scsi_transport_template> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sas_port_resume(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sas_port_suspend(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sas_queuecmd(Ptr<scsi_cmnd> cmd, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sas_scsi_ioctl(Ptr<ata_port> ap, Ptr<scsi_device> scsidev,
      @Unsigned int cmd, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sas_sdev_configure(Ptr<scsi_device> sdev, Ptr<queue_limits> lim,
      Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ata_scsi_activity_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_scsi_activity_store($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long ata_scsi_activity_store(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_scsi_add_hosts($arg1, (const struct scsi_host_template *)$arg2)")
  public static int ata_scsi_add_hosts(Ptr<ata_host> host, Ptr<scsi_host_template> sht) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_scsi_change_queue_depth(Ptr<scsi_device> sdev, int queue_depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_cmd_error_handler(Ptr<Scsi_Host> host, Ptr<ata_port> ap,
      Ptr<list_head> eh_work_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_scsi_dev_config(Ptr<scsi_device> sdev, Ptr<queue_limits> lim,
      Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_dev_rescan(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_scsi_dma_need_drain(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ata_scsi_em_message_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_scsi_em_message_store($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long ata_scsi_em_message_store(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ata_scsi_em_message_type_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_error(Ptr<Scsi_Host> host) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_scsi_find_dev($arg1, (const struct scsi_device *)$arg2)")
  public static Ptr<ata_device> ata_scsi_find_dev(Ptr<ata_port> ap, Ptr<scsi_device> scsidev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_flush_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_handle_link_detach(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_hotplug(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_scsi_ioctl(Ptr<scsi_device> scsidev, @Unsigned int cmd, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ata_scsi_lpm_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_scsi_lpm_store($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long ata_scsi_lpm_store(Ptr<device> device,
      Ptr<device_attribute> attr, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_scsi_lpm_supported(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ata_scsi_lpm_supported_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_media_change_notify(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_mode_select_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_scsi_offline_dev(Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long ata_scsi_park_show(Ptr<device> device,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_scsi_park_store($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long ata_scsi_park_store(Ptr<device> device,
      Ptr<device_attribute> attr, String buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_pass_thru(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_port_error_handler(Ptr<Scsi_Host> host, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_qc_complete(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ata_queued_cmd> ata_scsi_qc_new(Ptr<ata_device> dev, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_scsi_queuecmd(Ptr<Scsi_Host> shost, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_report_zones_complete(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_rw_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_scan_host(Ptr<ata_port> ap, int sync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_sdev_config(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_scsi_sdev_configure(Ptr<scsi_device> sdev, Ptr<queue_limits> lim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_sdev_destroy(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_scsi_sdev_init(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_security_inout_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_scsi_sense_is_valid(char sk, char asc, char ascq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_set_passthru_sense_fields(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_set_sense(Ptr<ata_device> dev, Ptr<scsi_cmnd> cmd, char sk, char asc,
      char ascq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_simulate(Ptr<ata_device> dev, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_start_stop_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_scsi_unlock_native_capacity(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_scsi_user_scan(Ptr<Scsi_Host> shost, @Unsigned int channel,
      @Unsigned int id, @Unsigned long lun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_var_len_cdb_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_verify_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_write_same_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_zbc_in_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsi_zbc_out_xlat(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsiop_inquiry(Ptr<ata_device> dev, Ptr<scsi_cmnd> cmd,
      Ptr<java.lang.Character> rbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsiop_maint_in(Ptr<ata_device> dev, Ptr<scsi_cmnd> cmd,
      Ptr<java.lang.Character> rbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsiop_mode_sense(Ptr<ata_device> dev, Ptr<scsi_cmnd> cmd,
      Ptr<java.lang.Character> rbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_scsiop_read_cap(Ptr<ata_device> dev, Ptr<scsi_cmnd> cmd,
      Ptr<java.lang.Character> rbuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_set_max_sectors(Ptr<ata_device> dev, @Unsigned long new_sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_set_mode(Ptr<ata_link> link, Ptr<Ptr<ata_device>> r_failed_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean ata_set_rwcmd_protocol(Ptr<ata_device> dev, Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sff_check_ready(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char ata_sff_check_status(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_sff_data_xfer(Ptr<ata_queued_cmd> qc, String buf,
      @Unsigned int buflen, int rw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_sff_data_xfer32(Ptr<ata_queued_cmd> qc, String buf,
      @Unsigned int buflen, int rw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_sff_dev_classify(Ptr<ata_device> dev, int present,
      Ptr<java.lang.Character> r_err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_dev_select(Ptr<ata_port> ap, @Unsigned int device) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_dma_pause(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_drain_fifo(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_error_handler(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_sff_exec_command($arg1, (const struct ata_taskfile *)$arg2)")
  public static void ata_sff_exec_command(Ptr<ata_port> ap, Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_flush_pio_task(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_freeze(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sff_hsm_move(Ptr<ata_port> ap, Ptr<ata_queued_cmd> qc, char status,
      int in_wq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sff_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn ata_sff_interrupt(int irq,
      Ptr<?> dev_instance) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_irq_on(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_lost_interrupt(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_pause(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_pio_task(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_port_init(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_sff_port_intr(Ptr<ata_port> ap, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_postreset(Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> classes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sff_prereset(Ptr<ata_link> link, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_qc_fill_rtf(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_sff_qc_issue(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_queue_delayed_work(Ptr<delayed_work> dwork, @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_queue_pio_task(Ptr<ata_link> link, @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_queue_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sff_softreset(Ptr<ata_link> link, Ptr<java.lang. @Unsigned Integer> classes,
      @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_std_ports(Ptr<ata_ioports> ioaddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_sff_tf_load($arg1, (const struct ata_taskfile *)$arg2)")
  public static void ata_sff_tf_load(Ptr<ata_port> ap, Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_tf_read(Ptr<ata_port> ap, Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sff_thaw(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sff_wait_after_reset(Ptr<ata_link> link, @Unsigned int devmask,
      @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_sff_wait_ready(Ptr<ata_link> link, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_sg_init(Ptr<ata_queued_cmd> qc, Ptr<scatterlist> sg,
      @Unsigned int n_elem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_show_ering(Ptr<ata_ering_entry> ent, Ptr<?> void_arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_slave_link_init(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_std_bios_param(Ptr<scsi_device> sdev, Ptr<block_device> bdev,
      @Unsigned @OriginalName("sector_t") long capacity, Ptr<java.lang.Integer> geom) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_std_end_eh(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_std_error_handler(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_std_postreset(Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> classes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_std_prereset(Ptr<ata_link> link, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_std_qc_defer(Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_std_sched_eh(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_task_ioctl(Ptr<scsi_device> scsidev, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_tdev_match(Ptr<attribute_container> cont, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_tdev_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_tf_from_fis((const u8 *)$arg1, $arg2)")
  public static void ata_tf_from_fis(Ptr<java.lang.Character> fis, Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_tf_init(Ptr<ata_device> dev, Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_tf_read_block((const struct ata_taskfile *)$arg1, $arg2)")
  public static @Unsigned long ata_tf_read_block(Ptr<ata_taskfile> tf, Ptr<ata_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_tf_to_fis((const struct ata_taskfile *)$arg1, $arg2, $arg3, $arg4)")
  public static void ata_tf_to_fis(Ptr<ata_taskfile> tf, char pmp, int is_cmd,
      Ptr<java.lang.Character> fis) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_tf_to_host($arg1, (const struct ata_taskfile *)$arg2, $arg3)")
  public static void ata_tf_to_host(Ptr<ata_port> ap, Ptr<ata_taskfile> tf, @Unsigned int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_tf_to_lba((const struct ata_taskfile *)$arg1)")
  public static @Unsigned long ata_tf_to_lba(Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_tf_to_lba48((const struct ata_taskfile *)$arg1)")
  public static @Unsigned long ata_tf_to_lba48(Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_timing_compute(Ptr<ata_device> adev, @Unsigned short speed,
      Ptr<ata_timing> t, int T, int UT) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char ata_timing_cycle2mode(@Unsigned int xfer_shift, int cycle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct ata_timing*)ata_timing_find_mode($arg1))")
  public static Ptr<ata_timing> ata_timing_find_mode(char xfer_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_timing_merge((const struct ata_timing *)$arg1, (const struct ata_timing *)$arg2, $arg3, $arg4)")
  public static void ata_timing_merge(Ptr<ata_timing> a, Ptr<ata_timing> b, Ptr<ata_timing> m,
      @Unsigned int what) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_tlink_add(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_tlink_delete(Ptr<ata_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_tlink_match(Ptr<attribute_container> cont, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_tlink_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_to_sense_error(char drv_stat, char drv_err, Ptr<java.lang.Character> sk,
      Ptr<java.lang.Character> asc, Ptr<java.lang.Character> ascq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_tport_add(Ptr<device> parent, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_tport_delete(Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_tport_match(Ptr<attribute_container> cont, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_tport_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ata_unpack_xfermask(@Unsigned int xfer_mask,
      Ptr<java.lang. @Unsigned Integer> pio_mask, Ptr<java.lang. @Unsigned Integer> mwdma_mask,
      Ptr<java.lang. @Unsigned Integer> udma_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_wait_after_reset($arg1, $arg2, (int (*)(struct ata_link*))$arg3)")
  public static int ata_wait_after_reset(Ptr<ata_link> link, @Unsigned long deadline,
      Ptr<?> check_ready) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ata_wait_ready($arg1, $arg2, (int (*)(struct ata_link*))$arg3)")
  public static int ata_wait_ready(Ptr<ata_link> link, @Unsigned long deadline,
      Ptr<?> check_ready) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_wait_register(Ptr<ata_port> ap, Ptr<?> reg, @Unsigned int mask,
      @Unsigned int val, @Unsigned int interval, @Unsigned int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char ata_xfer_mask2mode(@Unsigned int xfer_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ata_xfer_mode2mask(char xfer_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ata_xfer_mode2shift(char xfer_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 device; u8 reserved1; short unsigned int reserved2; unsigned int reserved3; long long unsigned int reserved4; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_of_device_path_of_edd_device_params_and_sata_of_device_path_of_edd_device_params extends Struct {
    public char device;

    public char reserved1;

    public @Unsigned short reserved2;

    public @Unsigned int reserved3;

    public @Unsigned long reserved4;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ata_quirks"
  )
  public enum ata_quirks implements Enum<ata_quirks>, TypedEnum<ata_quirks, java.lang. @Unsigned Integer> {
    /**
     * {@code __ATA_QUIRK_DIAGNOSTIC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "__ATA_QUIRK_DIAGNOSTIC"
    )
    __ATA_QUIRK_DIAGNOSTIC,

    /**
     * {@code __ATA_QUIRK_NODMA = 1}
     */
    @EnumMember(
        value = 1L,
        name = "__ATA_QUIRK_NODMA"
    )
    __ATA_QUIRK_NODMA,

    /**
     * {@code __ATA_QUIRK_NONCQ = 2}
     */
    @EnumMember(
        value = 2L,
        name = "__ATA_QUIRK_NONCQ"
    )
    __ATA_QUIRK_NONCQ,

    /**
     * {@code __ATA_QUIRK_MAX_SEC_128 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "__ATA_QUIRK_MAX_SEC_128"
    )
    __ATA_QUIRK_MAX_SEC_128,

    /**
     * {@code __ATA_QUIRK_BROKEN_HPA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "__ATA_QUIRK_BROKEN_HPA"
    )
    __ATA_QUIRK_BROKEN_HPA,

    /**
     * {@code __ATA_QUIRK_DISABLE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "__ATA_QUIRK_DISABLE"
    )
    __ATA_QUIRK_DISABLE,

    /**
     * {@code __ATA_QUIRK_HPA_SIZE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "__ATA_QUIRK_HPA_SIZE"
    )
    __ATA_QUIRK_HPA_SIZE,

    /**
     * {@code __ATA_QUIRK_IVB = 7}
     */
    @EnumMember(
        value = 7L,
        name = "__ATA_QUIRK_IVB"
    )
    __ATA_QUIRK_IVB,

    /**
     * {@code __ATA_QUIRK_STUCK_ERR = 8}
     */
    @EnumMember(
        value = 8L,
        name = "__ATA_QUIRK_STUCK_ERR"
    )
    __ATA_QUIRK_STUCK_ERR,

    /**
     * {@code __ATA_QUIRK_BRIDGE_OK = 9}
     */
    @EnumMember(
        value = 9L,
        name = "__ATA_QUIRK_BRIDGE_OK"
    )
    __ATA_QUIRK_BRIDGE_OK,

    /**
     * {@code __ATA_QUIRK_ATAPI_MOD16_DMA = 10}
     */
    @EnumMember(
        value = 10L,
        name = "__ATA_QUIRK_ATAPI_MOD16_DMA"
    )
    __ATA_QUIRK_ATAPI_MOD16_DMA,

    /**
     * {@code __ATA_QUIRK_FIRMWARE_WARN = 11}
     */
    @EnumMember(
        value = 11L,
        name = "__ATA_QUIRK_FIRMWARE_WARN"
    )
    __ATA_QUIRK_FIRMWARE_WARN,

    /**
     * {@code __ATA_QUIRK_1_5_GBPS = 12}
     */
    @EnumMember(
        value = 12L,
        name = "__ATA_QUIRK_1_5_GBPS"
    )
    __ATA_QUIRK_1_5_GBPS,

    /**
     * {@code __ATA_QUIRK_NOSETXFER = 13}
     */
    @EnumMember(
        value = 13L,
        name = "__ATA_QUIRK_NOSETXFER"
    )
    __ATA_QUIRK_NOSETXFER,

    /**
     * {@code __ATA_QUIRK_BROKEN_FPDMA_AA = 14}
     */
    @EnumMember(
        value = 14L,
        name = "__ATA_QUIRK_BROKEN_FPDMA_AA"
    )
    __ATA_QUIRK_BROKEN_FPDMA_AA,

    /**
     * {@code __ATA_QUIRK_DUMP_ID = 15}
     */
    @EnumMember(
        value = 15L,
        name = "__ATA_QUIRK_DUMP_ID"
    )
    __ATA_QUIRK_DUMP_ID,

    /**
     * {@code __ATA_QUIRK_MAX_SEC_LBA48 = 16}
     */
    @EnumMember(
        value = 16L,
        name = "__ATA_QUIRK_MAX_SEC_LBA48"
    )
    __ATA_QUIRK_MAX_SEC_LBA48,

    /**
     * {@code __ATA_QUIRK_ATAPI_DMADIR = 17}
     */
    @EnumMember(
        value = 17L,
        name = "__ATA_QUIRK_ATAPI_DMADIR"
    )
    __ATA_QUIRK_ATAPI_DMADIR,

    /**
     * {@code __ATA_QUIRK_NO_NCQ_TRIM = 18}
     */
    @EnumMember(
        value = 18L,
        name = "__ATA_QUIRK_NO_NCQ_TRIM"
    )
    __ATA_QUIRK_NO_NCQ_TRIM,

    /**
     * {@code __ATA_QUIRK_NOLPM = 19}
     */
    @EnumMember(
        value = 19L,
        name = "__ATA_QUIRK_NOLPM"
    )
    __ATA_QUIRK_NOLPM,

    /**
     * {@code __ATA_QUIRK_WD_BROKEN_LPM = 20}
     */
    @EnumMember(
        value = 20L,
        name = "__ATA_QUIRK_WD_BROKEN_LPM"
    )
    __ATA_QUIRK_WD_BROKEN_LPM,

    /**
     * {@code __ATA_QUIRK_ZERO_AFTER_TRIM = 21}
     */
    @EnumMember(
        value = 21L,
        name = "__ATA_QUIRK_ZERO_AFTER_TRIM"
    )
    __ATA_QUIRK_ZERO_AFTER_TRIM,

    /**
     * {@code __ATA_QUIRK_NO_DMA_LOG = 22}
     */
    @EnumMember(
        value = 22L,
        name = "__ATA_QUIRK_NO_DMA_LOG"
    )
    __ATA_QUIRK_NO_DMA_LOG,

    /**
     * {@code __ATA_QUIRK_NOTRIM = 23}
     */
    @EnumMember(
        value = 23L,
        name = "__ATA_QUIRK_NOTRIM"
    )
    __ATA_QUIRK_NOTRIM,

    /**
     * {@code __ATA_QUIRK_MAX_SEC_1024 = 24}
     */
    @EnumMember(
        value = 24L,
        name = "__ATA_QUIRK_MAX_SEC_1024"
    )
    __ATA_QUIRK_MAX_SEC_1024,

    /**
     * {@code __ATA_QUIRK_MAX_TRIM_128M = 25}
     */
    @EnumMember(
        value = 25L,
        name = "__ATA_QUIRK_MAX_TRIM_128M"
    )
    __ATA_QUIRK_MAX_TRIM_128M,

    /**
     * {@code __ATA_QUIRK_NO_NCQ_ON_ATI = 26}
     */
    @EnumMember(
        value = 26L,
        name = "__ATA_QUIRK_NO_NCQ_ON_ATI"
    )
    __ATA_QUIRK_NO_NCQ_ON_ATI,

    /**
     * {@code __ATA_QUIRK_NO_LPM_ON_ATI = 27}
     */
    @EnumMember(
        value = 27L,
        name = "__ATA_QUIRK_NO_LPM_ON_ATI"
    )
    __ATA_QUIRK_NO_LPM_ON_ATI,

    /**
     * {@code __ATA_QUIRK_NO_ID_DEV_LOG = 28}
     */
    @EnumMember(
        value = 28L,
        name = "__ATA_QUIRK_NO_ID_DEV_LOG"
    )
    __ATA_QUIRK_NO_ID_DEV_LOG,

    /**
     * {@code __ATA_QUIRK_NO_LOG_DIR = 29}
     */
    @EnumMember(
        value = 29L,
        name = "__ATA_QUIRK_NO_LOG_DIR"
    )
    __ATA_QUIRK_NO_LOG_DIR,

    /**
     * {@code __ATA_QUIRK_NO_FUA = 30}
     */
    @EnumMember(
        value = 30L,
        name = "__ATA_QUIRK_NO_FUA"
    )
    __ATA_QUIRK_NO_FUA,

    /**
     * {@code __ATA_QUIRK_MAX = 31}
     */
    @EnumMember(
        value = 31L,
        name = "__ATA_QUIRK_MAX"
    )
    __ATA_QUIRK_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ata_prot_flags"
  )
  public enum ata_prot_flags implements Enum<ata_prot_flags>, TypedEnum<ata_prot_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code ATA_PROT_FLAG_PIO = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ATA_PROT_FLAG_PIO"
    )
    ATA_PROT_FLAG_PIO,

    /**
     * {@code ATA_PROT_FLAG_DMA = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ATA_PROT_FLAG_DMA"
    )
    ATA_PROT_FLAG_DMA,

    /**
     * {@code ATA_PROT_FLAG_NCQ = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ATA_PROT_FLAG_NCQ"
    )
    ATA_PROT_FLAG_NCQ,

    /**
     * {@code ATA_PROT_FLAG_ATAPI = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ATA_PROT_FLAG_ATAPI"
    )
    ATA_PROT_FLAG_ATAPI,

    /**
     * {@code ATA_PROT_UNKNOWN = 255}
     */
    @EnumMember(
        value = 255L,
        name = "ATA_PROT_UNKNOWN"
    )
    ATA_PROT_UNKNOWN,

    /**
     * {@code ATA_PROT_NODATA = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ATA_PROT_NODATA"
    )
    ATA_PROT_NODATA,

    /**
     * {@code ATA_PROT_PIO = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ATA_PROT_PIO"
    )
    ATA_PROT_PIO,

    /**
     * {@code ATA_PROT_DMA = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ATA_PROT_DMA"
    )
    ATA_PROT_DMA,

    /**
     * {@code ATA_PROT_NCQ_NODATA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ATA_PROT_NCQ_NODATA"
    )
    ATA_PROT_NCQ_NODATA,

    /**
     * {@code ATA_PROT_NCQ = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ATA_PROT_NCQ"
    )
    ATA_PROT_NCQ,

    /**
     * {@code ATAPI_PROT_NODATA = 8}
     */
    @EnumMember(
        value = 8L,
        name = "ATAPI_PROT_NODATA"
    )
    ATAPI_PROT_NODATA,

    /**
     * {@code ATAPI_PROT_PIO = 9}
     */
    @EnumMember(
        value = 9L,
        name = "ATAPI_PROT_PIO"
    )
    ATAPI_PROT_PIO,

    /**
     * {@code ATAPI_PROT_DMA = 10}
     */
    @EnumMember(
        value = 10L,
        name = "ATAPI_PROT_DMA"
    )
    ATAPI_PROT_DMA
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_bmdma_prd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_bmdma_prd extends Struct {
    public @Unsigned @OriginalName("__le32") int addr;

    public @Unsigned @OriginalName("__le32") int flags_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ata_xfer_mask"
  )
  public enum ata_xfer_mask implements Enum<ata_xfer_mask>, TypedEnum<ata_xfer_mask, java.lang. @Unsigned Integer> {
    /**
     * {@code ATA_MASK_PIO = 127}
     */
    @EnumMember(
        value = 127L,
        name = "ATA_MASK_PIO"
    )
    ATA_MASK_PIO,

    /**
     * {@code ATA_MASK_MWDMA = 3968}
     */
    @EnumMember(
        value = 3968L,
        name = "ATA_MASK_MWDMA"
    )
    ATA_MASK_MWDMA,

    /**
     * {@code ATA_MASK_UDMA = 1044480}
     */
    @EnumMember(
        value = 1044480L,
        name = "ATA_MASK_UDMA"
    )
    ATA_MASK_UDMA
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ata_completion_errors"
  )
  public enum ata_completion_errors implements Enum<ata_completion_errors>, TypedEnum<ata_completion_errors, java.lang. @Unsigned Integer> {
    /**
     * {@code AC_ERR_OK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "AC_ERR_OK"
    )
    AC_ERR_OK,

    /**
     * {@code AC_ERR_DEV = 1}
     */
    @EnumMember(
        value = 1L,
        name = "AC_ERR_DEV"
    )
    AC_ERR_DEV,

    /**
     * {@code AC_ERR_HSM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "AC_ERR_HSM"
    )
    AC_ERR_HSM,

    /**
     * {@code AC_ERR_TIMEOUT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "AC_ERR_TIMEOUT"
    )
    AC_ERR_TIMEOUT,

    /**
     * {@code AC_ERR_MEDIA = 8}
     */
    @EnumMember(
        value = 8L,
        name = "AC_ERR_MEDIA"
    )
    AC_ERR_MEDIA,

    /**
     * {@code AC_ERR_ATA_BUS = 16}
     */
    @EnumMember(
        value = 16L,
        name = "AC_ERR_ATA_BUS"
    )
    AC_ERR_ATA_BUS,

    /**
     * {@code AC_ERR_HOST_BUS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "AC_ERR_HOST_BUS"
    )
    AC_ERR_HOST_BUS,

    /**
     * {@code AC_ERR_SYSTEM = 64}
     */
    @EnumMember(
        value = 64L,
        name = "AC_ERR_SYSTEM"
    )
    AC_ERR_SYSTEM,

    /**
     * {@code AC_ERR_INVALID = 128}
     */
    @EnumMember(
        value = 128L,
        name = "AC_ERR_INVALID"
    )
    AC_ERR_INVALID,

    /**
     * {@code AC_ERR_OTHER = 256}
     */
    @EnumMember(
        value = 256L,
        name = "AC_ERR_OTHER"
    )
    AC_ERR_OTHER,

    /**
     * {@code AC_ERR_NODEV_HINT = 512}
     */
    @EnumMember(
        value = 512L,
        name = "AC_ERR_NODEV_HINT"
    )
    AC_ERR_NODEV_HINT,

    /**
     * {@code AC_ERR_NCQ = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "AC_ERR_NCQ"
    )
    AC_ERR_NCQ
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ata_lpm_policy"
  )
  public enum ata_lpm_policy implements Enum<ata_lpm_policy>, TypedEnum<ata_lpm_policy, java.lang. @Unsigned Integer> {
    /**
     * {@code ATA_LPM_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ATA_LPM_UNKNOWN"
    )
    ATA_LPM_UNKNOWN,

    /**
     * {@code ATA_LPM_MAX_POWER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ATA_LPM_MAX_POWER"
    )
    ATA_LPM_MAX_POWER,

    /**
     * {@code ATA_LPM_MED_POWER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ATA_LPM_MED_POWER"
    )
    ATA_LPM_MED_POWER,

    /**
     * {@code ATA_LPM_MED_POWER_WITH_DIPM = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ATA_LPM_MED_POWER_WITH_DIPM"
    )
    ATA_LPM_MED_POWER_WITH_DIPM,

    /**
     * {@code ATA_LPM_MIN_POWER_WITH_PARTIAL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ATA_LPM_MIN_POWER_WITH_PARTIAL"
    )
    ATA_LPM_MIN_POWER_WITH_PARTIAL,

    /**
     * {@code ATA_LPM_MIN_POWER = 5}
     */
    @EnumMember(
        value = 5L,
        name = "ATA_LPM_MIN_POWER"
    )
    ATA_LPM_MIN_POWER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_queued_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_queued_cmd extends Struct {
    public Ptr<ata_port> ap;

    public Ptr<ata_device> dev;

    public Ptr<scsi_cmnd> scsicmd;

    public Ptr<?> scsidone;

    public ata_taskfile tf;

    public char @Size(16) [] cdb;

    public @Unsigned long flags;

    public @Unsigned int tag;

    public @Unsigned int hw_tag;

    public @Unsigned int n_elem;

    public @Unsigned int orig_n_elem;

    public int dma_dir;

    public @Unsigned int sect_size;

    public @Unsigned int nbytes;

    public @Unsigned int extrabytes;

    public @Unsigned int curbytes;

    public scatterlist sgent;

    public Ptr<scatterlist> sg;

    public Ptr<scatterlist> cursg;

    public @Unsigned int cursg_ofs;

    public @Unsigned int err_mask;

    public ata_taskfile result_tf;

    public @OriginalName("ata_qc_cb_t") Ptr<?> complete_fn;

    public Ptr<?> private_data;

    public Ptr<?> lldd_task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_link"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_link extends Struct {
    public Ptr<ata_port> ap;

    public int pmp;

    public device tdev;

    public @Unsigned int active_tag;

    public @Unsigned int sactive;

    public @Unsigned int flags;

    public @Unsigned int saved_scontrol;

    public @Unsigned int hw_sata_spd_limit;

    public @Unsigned int sata_spd_limit;

    public @Unsigned int sata_spd;

    public ata_lpm_policy lpm_policy;

    public ata_eh_info eh_info;

    public ata_eh_context eh_context;

    public ata_device @Size(2) [] device;

    public @Unsigned long last_lpm_change;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_taskfile"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_taskfile extends Struct {
    public @Unsigned long flags;

    public char protocol;

    public char ctl;

    public char hob_feature;

    public char hob_nsect;

    public char hob_lbal;

    public char hob_lbam;

    public char hob_lbah;

    @InlineUnion(47035)
    public char error;

    @InlineUnion(47035)
    public char feature;

    public char nsect;

    public char lbal;

    public char lbam;

    public char lbah;

    public char device;

    @InlineUnion(47036)
    public char status;

    @InlineUnion(47036)
    public char command;

    public @Unsigned int auxiliary;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_ioports"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_ioports extends Struct {
    public Ptr<?> cmd_addr;

    public Ptr<?> data_addr;

    public Ptr<?> error_addr;

    public Ptr<?> feature_addr;

    public Ptr<?> nsect_addr;

    public Ptr<?> lbal_addr;

    public Ptr<?> lbam_addr;

    public Ptr<?> lbah_addr;

    public Ptr<?> device_addr;

    public Ptr<?> status_addr;

    public Ptr<?> command_addr;

    public Ptr<?> altstatus_addr;

    public Ptr<?> ctl_addr;

    public Ptr<?> bmdma_addr;

    public Ptr<?> scr_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_host"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_host extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<device> dev;

    public Ptr<Ptr<?>> iomap;

    public @Unsigned int n_ports;

    public @Unsigned int n_tags;

    public Ptr<?> private_data;

    public Ptr<ata_port_operations> ops;

    public @Unsigned long flags;

    public kref kref;

    public mutex eh_mutex;

    public Ptr<task_struct> eh_owner;

    public Ptr<ata_port> simplex_claimed;

    public Ptr<ata_port> @Size(0) [] ports;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_port_operations"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_port_operations extends Struct {
    public Ptr<?> qc_defer;

    public Ptr<?> check_atapi_dma;

    public Ptr<?> qc_prep;

    public Ptr<?> qc_issue;

    public Ptr<?> qc_fill_rtf;

    public Ptr<?> qc_ncq_fill_rtf;

    public Ptr<?> cable_detect;

    public Ptr<?> mode_filter;

    public Ptr<?> set_piomode;

    public Ptr<?> set_dmamode;

    public Ptr<?> set_mode;

    public Ptr<?> read_id;

    public Ptr<?> dev_config;

    public Ptr<?> freeze;

    public Ptr<?> thaw;

    public ata_reset_operations reset;

    public ata_reset_operations pmp_reset;

    public Ptr<?> error_handler;

    public Ptr<?> lost_interrupt;

    public Ptr<?> post_internal_cmd;

    public Ptr<?> sched_eh;

    public Ptr<?> end_eh;

    public Ptr<?> scr_read;

    public Ptr<?> scr_write;

    public Ptr<?> pmp_attach;

    public Ptr<?> pmp_detach;

    public Ptr<?> set_lpm;

    public Ptr<?> port_suspend;

    public Ptr<?> port_resume;

    public Ptr<?> port_start;

    public Ptr<?> port_stop;

    public Ptr<?> host_stop;

    public Ptr<?> sff_dev_select;

    public Ptr<?> sff_set_devctl;

    public Ptr<?> sff_check_status;

    public Ptr<?> sff_check_altstatus;

    public Ptr<?> sff_tf_load;

    public Ptr<?> sff_tf_read;

    public Ptr<?> sff_exec_command;

    public Ptr<?> sff_data_xfer;

    public Ptr<?> sff_irq_on;

    public Ptr<?> sff_irq_check;

    public Ptr<?> sff_irq_clear;

    public Ptr<?> sff_drain_fifo;

    public Ptr<?> bmdma_setup;

    public Ptr<?> bmdma_start;

    public Ptr<?> bmdma_stop;

    public Ptr<?> bmdma_status;

    public Ptr<?> em_show;

    public Ptr<?> em_store;

    public Ptr<?> sw_activity_show;

    public Ptr<?> sw_activity_store;

    public Ptr<?> transmit_led_message;

    public Ptr<ata_port_operations> inherits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_port"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_port extends Struct {
    public Ptr<Scsi_Host> scsi_host;

    public Ptr<ata_port_operations> ops;

    public Ptr<@OriginalName("spinlock_t") spinlock> lock;

    public @Unsigned long flags;

    public @Unsigned int pflags;

    public @Unsigned int print_id;

    public @Unsigned int port_no;

    public ata_ioports ioaddr;

    public char ctl;

    public char last_ctl;

    public Ptr<ata_link> sff_pio_task_link;

    public delayed_work sff_pio_task;

    public Ptr<ata_bmdma_prd> bmdma_prd;

    public @Unsigned @OriginalName("dma_addr_t") long bmdma_prd_dma;

    public @Unsigned int pio_mask;

    public @Unsigned int mwdma_mask;

    public @Unsigned int udma_mask;

    public @Unsigned int cbl;

    public ata_queued_cmd @Size(33) [] qcmd;

    public @Unsigned long qc_active;

    public int nr_active_links;

    public ata_link link;

    public Ptr<ata_link> slave_link;

    public int nr_pmp_links;

    public Ptr<ata_link> pmp_link;

    public Ptr<ata_link> excl_link;

    public ata_port_stats stats;

    public Ptr<ata_host> host;

    public Ptr<device> dev;

    public device tdev;

    public mutex scsi_scan_mutex;

    public delayed_work hotplug_task;

    public delayed_work scsi_rescan_task;

    public @Unsigned int hsm_task_state;

    public list_head eh_done_q;

    public @OriginalName("wait_queue_head_t") wait_queue_head eh_wait_q;

    public int eh_tries;

    public completion park_req_pending;

    public @OriginalName("pm_message_t") pm_message pm_mesg;

    public ata_lpm_policy target_lpm_policy;

    public timer_list fastdrain_timer;

    public @Unsigned int fastdrain_cnt;

    public @Unsigned @OriginalName("async_cookie_t") long cookie;

    public int em_message_type;

    public Ptr<?> private_data;

    public ata_acpi_gtm __acpi_init_gtm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_device extends Struct {
    public Ptr<ata_link> link;

    public @Unsigned int devno;

    public @Unsigned int quirks;

    public @Unsigned long flags;

    public Ptr<scsi_device> sdev;

    public Ptr<?> private_data;

    public Ptr<acpi_object> gtf_cache;

    public @Unsigned int gtf_filter;

    public Ptr<?> zpodd;

    public device tdev;

    public @Unsigned long n_sectors;

    public @Unsigned long n_native_sectors;

    public @Unsigned int _class;

    public @Unsigned long unpark_deadline;

    public char pio_mode;

    public char dma_mode;

    public char xfer_mode;

    public @Unsigned int xfer_shift;

    public @Unsigned int multi_count;

    public @Unsigned int max_sectors;

    public @Unsigned int cdb_len;

    public @Unsigned int pio_mask;

    public @Unsigned int mwdma_mask;

    public @Unsigned int udma_mask;

    public @Unsigned short cylinders;

    public @Unsigned short heads;

    public @Unsigned short sectors;

    @InlineUnion(47059)
    public @Unsigned short @Size(256) [] id;

    @InlineUnion(47059)
    public @Unsigned int @Size(128) [] gscr;

    public char @Size(512) [] gp_log_dir;

    public char @Size(8) [] devslp_timing;

    public char @Size(20) [] ncq_send_recv_cmds;

    public char @Size(64) [] ncq_non_data_cmds;

    public @Unsigned int zac_zoned_cap;

    public @Unsigned int zac_zones_optimal_open;

    public @Unsigned int zac_zones_optimal_nonseq;

    public @Unsigned int zac_zones_max_open;

    public Ptr<ata_cpr_log> cpr_log;

    public Ptr<ata_cdl> cdl;

    public int spdn_cnt;

    public ata_ering ering;

    public char @Size(512) [] sector_buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_port_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_port_stats extends Struct {
    public @Unsigned long unhandled_irq;

    public @Unsigned long idle_irq;

    public @Unsigned long rw_reqbuf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_ering_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_ering_entry extends Struct {
    public @Unsigned int eflags;

    public @Unsigned int err_mask;

    public @Unsigned long timestamp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_ering"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_ering extends Struct {
    public int cursor;

    public ata_ering_entry @Size(32) [] ring;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_cpr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_cpr extends Struct {
    public char num;

    public char num_storage_elements;

    public @Unsigned long start_lba;

    public @Unsigned long num_lbas;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_cpr_log"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_cpr_log extends Struct {
    public char nr_cpr;

    public ata_cpr @Size(0) [] cpr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_cdl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_cdl extends Struct {
    public char @Size(512) [] desc_log_buf;

    public char @Size(1024) [] ncq_sense_log_buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_eh_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_eh_info extends Struct {
    public Ptr<ata_device> dev;

    public @Unsigned int serror;

    public @Unsigned int err_mask;

    public @Unsigned int action;

    public @Unsigned int @Size(2) [] dev_action;

    public @Unsigned int flags;

    public @Unsigned int probe_mask;

    public char @Size(80) [] desc;

    public int desc_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_eh_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_eh_context extends Struct {
    public ata_eh_info i;

    public int @Size(2) [] tries;

    public int @Size(16) [] cmd_timeout_idx;

    public @Unsigned int @Size(2) [] classes;

    public @Unsigned int did_probe_mask;

    public @Unsigned int unloaded_mask;

    public @Unsigned int saved_ncq_enabled;

    public char @Size(2) [] saved_xfer_mode;

    public @Unsigned long last_reset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_acpi_drive"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_acpi_drive extends Struct {
    public @Unsigned int pio;

    public @Unsigned int dma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_acpi_gtm"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_acpi_gtm extends Struct {
    public ata_acpi_drive @Size(2) [] drive;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_reset_operations"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_reset_operations extends Struct {
    public @OriginalName("ata_prereset_fn_t") Ptr<?> prereset;

    public @OriginalName("ata_reset_fn_t") Ptr<?> softreset;

    public @OriginalName("ata_reset_fn_t") Ptr<?> hardreset;

    public @OriginalName("ata_postreset_fn_t") Ptr<?> postreset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_port_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_port_info extends Struct {
    public @Unsigned long flags;

    public @Unsigned long link_flags;

    public @Unsigned int pio_mask;

    public @Unsigned int mwdma_mask;

    public @Unsigned int udma_mask;

    public Ptr<ata_port_operations> port_ops;

    public Ptr<?> private_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_timing"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_timing extends Struct {
    public @Unsigned short mode;

    public @Unsigned short setup;

    public @Unsigned short act8b;

    public @Unsigned short rec8b;

    public @Unsigned short cyc8b;

    public @Unsigned short active;

    public @Unsigned short recover;

    public @Unsigned short dmack_hold;

    public @Unsigned short cycle;

    public @Unsigned short udma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ata_link_iter_mode"
  )
  public enum ata_link_iter_mode implements Enum<ata_link_iter_mode>, TypedEnum<ata_link_iter_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code ATA_LITER_EDGE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ATA_LITER_EDGE"
    )
    ATA_LITER_EDGE,

    /**
     * {@code ATA_LITER_HOST_FIRST = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ATA_LITER_HOST_FIRST"
    )
    ATA_LITER_HOST_FIRST,

    /**
     * {@code ATA_LITER_PMP_FIRST = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ATA_LITER_PMP_FIRST"
    )
    ATA_LITER_PMP_FIRST
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ata_dev_iter_mode"
  )
  public enum ata_dev_iter_mode implements Enum<ata_dev_iter_mode>, TypedEnum<ata_dev_iter_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code ATA_DITER_ENABLED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ATA_DITER_ENABLED"
    )
    ATA_DITER_ENABLED,

    /**
     * {@code ATA_DITER_ENABLED_REVERSE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ATA_DITER_ENABLED_REVERSE"
    )
    ATA_DITER_ENABLED_REVERSE,

    /**
     * {@code ATA_DITER_ALL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ATA_DITER_ALL"
    )
    ATA_DITER_ALL,

    /**
     * {@code ATA_DITER_ALL_REVERSE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ATA_DITER_ALL_REVERSE"
    )
    ATA_DITER_ALL_REVERSE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_force_param"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_force_param extends Struct {
    public String name;

    public char cbl;

    public char spd_limit;

    public @Unsigned int xfer_mask;

    public @Unsigned int quirk_on;

    public @Unsigned int quirk_off;

    public @Unsigned int pflags_on;

    public @Unsigned short lflags_on;

    public @Unsigned short lflags_off;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_force_ent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_force_ent extends Struct {
    public int port;

    public int device;

    public ata_force_param param;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_xfer_ent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_xfer_ent extends Struct {
    public int shift;

    public int bits;

    public char base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_dev_quirks_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_dev_quirks_entry extends Struct {
    public String model_num;

    public String model_rev;

    public @Unsigned int quirks;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ata_lpm_hints"
  )
  public enum ata_lpm_hints implements Enum<ata_lpm_hints>, TypedEnum<ata_lpm_hints, java.lang. @Unsigned Integer> {
    /**
     * {@code ATA_LPM_EMPTY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ATA_LPM_EMPTY"
    )
    ATA_LPM_EMPTY,

    /**
     * {@code ATA_LPM_HIPM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ATA_LPM_HIPM"
    )
    ATA_LPM_HIPM,

    /**
     * {@code ATA_LPM_WAKE_ONLY = 4}
     */
    @EnumMember(
        value = 4L,
        name = "ATA_LPM_WAKE_ONLY"
    )
    ATA_LPM_WAKE_ONLY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_eh_cmd_timeout_ent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_eh_cmd_timeout_ent extends Struct {
    public Ptr<java.lang.Character> commands;

    public Ptr<java.lang. @Unsigned Integer> timeouts;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_internal"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_internal extends Struct {
    public scsi_transport_template t;

    public device_attribute @Size(3) [] private_port_attrs;

    public device_attribute @Size(3) [] private_link_attrs;

    public device_attribute @Size(9) [] private_dev_attrs;

    public transport_container link_attr_cont;

    public transport_container dev_attr_cont;

    public Ptr<device_attribute> @Size(4) [] link_attrs;

    public Ptr<device_attribute> @Size(4) [] port_attrs;

    public Ptr<device_attribute> @Size(10) [] dev_attrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_show_ering_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_show_ering_arg extends Struct {
    public String buf;

    public int written;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_acpi_gtf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_acpi_gtf extends Struct {
    public char @Size(7) [] tf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ata_acpi_hotplug_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ata_acpi_hotplug_context extends Struct {
    public acpi_hotplug_context hp;

    public data_of_ata_acpi_hotplug_context data;
  }
}
